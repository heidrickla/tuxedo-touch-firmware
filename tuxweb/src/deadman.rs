//! The deadman that hands the panel back to the vendor if nobody is watching.
//!
//! Stage 6 lists this first among the mandatory safety features, and the reason
//! is `tls/THREAT-MODEL.md` §8: `supervis` is the sole `/dev/watchdog` kicker
//! and disarms the keepalive after 24 relaunches, so a replacement that fails
//! to start does not fail quietly — it resets the unit. During the cutover
//! window `tuxweb` holds the reply queue as sole reader, and if it hangs there
//! with nobody at the keyboard, the vendor never comes back on its own.
//!
//! So: a timer armed at startup, reset by an authenticated call, and on expiry
//! the process `execve`s the vendor binary. The panel returns to a working
//! stack by itself. That is what makes the stage revertible without anyone
//! being present, and it is why the window is bounded by construction rather
//! than by discipline.
//!
//! Three properties this is built around, all of them learned the hard way
//! elsewhere in this project:
//!
//! * **It must fire even if the main thread is wedged.** The timer lives on its
//!   own thread and shares nothing but a deadline, so a stuck reader cannot
//!   also stop the recovery.
//! * **It must not fire twice.** `execve` replaces the image, but a double fire
//!   racing itself before that lands would be two processes fighting over the
//!   queues. One-shot, enforced by an atomic.
//! * **Reset must be cheap and non-blocking**, because it happens on the
//!   request path.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default window. Stage 6 says 15 minutes, which is the length of the booked
/// session; anything longer stops being a deadman and becomes a nap.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(15 * 60);

/// How often the thread checks. The deadline is absolute, so this only bounds
/// how late the fire can be, not whether it happens.
const TICK: Duration = Duration::from_millis(500);

pub struct Deadman {
    /// Milliseconds since `origin`. An integer rather than an `Instant` so the
    /// request path can reset with a single relaxed store and no lock.
    deadline_ms: Arc<AtomicU64>,
    origin: Instant,
    window: Duration,
    fired: Arc<AtomicBool>,
    /// Cleared to stop the thread on an orderly shutdown, so a test — or a
    /// clean exit — does not leave a thread waiting to exec.
    running: Arc<AtomicBool>,
}

impl Deadman {
    /// Arm the timer. `action` runs once, on the timer thread, when the
    /// deadline passes without a reset.
    ///
    /// In production `action` is the handover to the vendor. It is injected
    /// rather than hardcoded so the firing logic can be tested without a test
    /// that replaces its own process image.
    pub fn arm<F>(window: Duration, action: F) -> Deadman
    where
        F: FnOnce() + Send + 'static,
    {
        let origin = Instant::now();
        let deadline_ms = Arc::new(AtomicU64::new(window.as_millis() as u64));
        let fired = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));

        let d = Deadman {
            deadline_ms: Arc::clone(&deadline_ms),
            origin,
            window,
            fired: Arc::clone(&fired),
            running: Arc::clone(&running),
        };

        std::thread::spawn(move || {
            let mut action = Some(action);
            loop {
                if !running.load(Ordering::Relaxed) {
                    return;
                }
                let elapsed = origin.elapsed().as_millis() as u64;
                if elapsed >= deadline_ms.load(Ordering::Relaxed) {
                    // compare_exchange, not a load-then-store: two ticks must
                    // never both decide they are the one that fires
                    if fired
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        if let Some(f) = action.take() {
                            f();
                        }
                    }
                    return;
                }
                std::thread::sleep(TICK);
            }
        });
        d
    }

    /// Push the deadline out by a full window from now.
    ///
    /// Ignored once fired: a reset arriving after the handover has begun must
    /// not look like it worked.
    pub fn reset(&self) -> bool {
        if self.fired.load(Ordering::SeqCst) {
            return false;
        }
        let next = self.origin.elapsed().as_millis() as u64 + self.window.as_millis() as u64;
        self.deadline_ms.store(next, Ordering::Relaxed);
        true
    }

    pub fn remaining(&self) -> Duration {
        let dl = self.deadline_ms.load(Ordering::Relaxed);
        let now = self.origin.elapsed().as_millis() as u64;
        Duration::from_millis(dl.saturating_sub(now))
    }

    pub fn has_fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }

    /// Fire now, without waiting. This is the "fall back now" control: stage 6
    /// lists an authenticated immediate revert alongside the timer, and it is
    /// the same code path so it cannot rot separately from the one that gets
    /// exercised.
    pub fn trip(&self) {
        self.deadline_ms.store(0, Ordering::Relaxed);
    }

    /// Stop the timer thread without firing. For an orderly shutdown only.
    pub fn disarm(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// The production action: close nothing, exec the vendor, keep the pid.
///
/// Everything `tuxweb` opened is `FD_CLOEXEC`, so the exec is the close. That
/// is deliberate — an explicit teardown here would be code running in the
/// failure path, which is the worst place to put code that can itself fail.
///
/// `supervis` matches on `comm`, which follows the exec'd basename, and the
/// vendor keeps the basename `Barracuda` at `vendor/Barracuda`. Proven in
/// stage 5 on the panel.
pub fn hand_back_to_vendor(target: &str) -> ! {
    use std::os::unix::process::CommandExt;
    eprintln!("tuxweb: DEADMAN -- handing the panel back to {target}");
    let err = std::process::Command::new(target)
        .arg0("/opt/webserver/Barracuda")
        .exec();
    // Reaching here means the panel is now running nothing. supervis will
    // relaunch whatever is at the vendor path within ~5 s (§5.2), so exiting
    // is the correct move and staying alive holding the queues is not.
    eprintln!("tuxweb: DEADMAN EXEC FAILED: {err}");
    eprintln!("tuxweb: exiting so supervis relaunches the vendor path");
    std::process::exit(3);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn counter() -> (Arc<AtomicUsize>, impl FnOnce() + Send + 'static) {
        let n = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&n);
        (n, move || {
            c.fetch_add(1, Ordering::SeqCst);
        })
    }

    #[test]
    fn it_fires_when_nobody_resets_it() {
        let (n, act) = counter();
        let d = Deadman::arm(Duration::from_millis(150), act);
        assert_eq!(n.load(Ordering::SeqCst), 0, "must not fire early");
        std::thread::sleep(Duration::from_millis(900));
        assert_eq!(n.load(Ordering::SeqCst), 1, "must fire once the window passes");
        assert!(d.has_fired());
    }

    #[test]
    fn resetting_keeps_it_from_firing() {
        let (n, act) = counter();
        let d = Deadman::arm(Duration::from_millis(400), act);
        // four resets across more than two windows
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(200));
            assert!(d.reset(), "reset must be accepted while unfired");
        }
        assert_eq!(n.load(Ordering::SeqCst), 0, "resets must hold it off");
        assert!(!d.has_fired());
    }

    #[test]
    fn it_fires_exactly_once() {
        let (n, act) = counter();
        let d = Deadman::arm(Duration::from_millis(80), act);
        std::thread::sleep(Duration::from_millis(700));
        // a reset after firing must be refused rather than silently ignored:
        // a caller that thinks it extended the window is worse than an error
        assert!(!d.reset(), "reset after firing must report failure");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(n.load(Ordering::SeqCst), 1, "must not fire twice");
    }

    #[test]
    fn trip_fires_immediately() {
        let (n, act) = counter();
        let d = Deadman::arm(Duration::from_secs(3600), act);
        assert!(d.remaining() > Duration::from_secs(3000));
        d.trip();
        std::thread::sleep(Duration::from_millis(900));
        assert_eq!(n.load(Ordering::SeqCst), 1, "the manual revert uses the same path");
    }

    #[test]
    fn disarm_stops_it_without_firing() {
        let (n, act) = counter();
        let d = Deadman::arm(Duration::from_millis(200), act);
        d.disarm();
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(n.load(Ordering::SeqCst), 0, "an orderly shutdown must not exec");
    }

    #[test]
    fn remaining_counts_down_and_resets_restore_the_full_window() {
        let (_n, act) = counter();
        let d = Deadman::arm(Duration::from_secs(10), act);
        std::thread::sleep(Duration::from_millis(300));
        let after_wait = d.remaining();
        assert!(after_wait < Duration::from_secs(10));
        d.reset();
        assert!(d.remaining() > after_wait, "reset must restore the window");
        d.disarm();
    }

    #[test]
    fn the_default_window_is_the_booked_session_length() {
        // 15 minutes is what stage 6 books. A longer default would quietly turn
        // the deadman into something that outlives the person watching it.
        assert_eq!(DEFAULT_WINDOW, Duration::from_secs(900));
    }
}
