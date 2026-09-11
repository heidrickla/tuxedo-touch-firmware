//! POSIX message queues, opened the way stage 6 requires and no other way.
//!
//! Three of the five mandatory safety features for the cutover live here, and
//! each of them is a rule about what this code must NOT do:
//!
//! * **Never create a queue.** Blocker B4: `/tuxedo` creates the queues with
//!   its own geometry, and a queue created by us with different attributes
//!   would be a second, wrong queue that the vendor never writes to — failing
//!   in the shape of "the panel went quiet", which is the hardest shape to
//!   diagnose. `O_CREAT` is not merely unused here, `open_flags` is a pure
//!   function asserted by a test to never contain it.
//! * **`FD_CLOEXEC` on everything.** The deadman hands the panel back by
//!   `execve`, and the exec is what closes our descriptors. A queue that
//!   survived into the vendor's image would be a descriptor it never asked for,
//!   held on a queue it expects to own.
//! * **Receive only, with a timeout.** The reader thread does nothing else, and
//!   a bounded receive is what lets it notice a shutdown rather than sitting in
//!   an uninterruptible wait while the deadman tries to exec around it.
//!
//! One more thing that is not a policy but a fact worth encoding: `mq_receive`
//! fails with `EMSGSIZE` unless the buffer is at least `mq_msgsize`. The
//! measured geometry is 556 bytes on `/Q_ServCmdTrsmtr` (§ stage 2), but the
//! buffer is sized from `mq_getattr` at runtime rather than from that constant,
//! because a hardcoded size that is one byte small fails every receive and
//! looks exactly like a silent panel.

use std::ffi::CString;
use std::time::Duration;

/// The queues, by the names `/tuxedo` creates them under.
pub const REPLIES: &str = "/Q_ServCmdTrsmtr";
pub const COMMANDS: &str = "/Q_ServCmdRcver";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Attr {
    pub flags: i64,
    pub maxmsg: i64,
    pub msgsize: i64,
    pub curmsgs: i64,
}

/// Flags for opening an existing queue.
///
/// Split out as a pure function purely so a test can assert what is NOT in it.
/// The rule "never create a queue" is worth more as an executable check than as
/// a comment, because the failure it prevents is silent.
pub fn open_flags(read_only: bool) -> i32 {
    let access = if read_only { libc::O_RDONLY } else { libc::O_RDWR };
    access | libc::O_CLOEXEC
}

#[derive(Debug)]
pub struct Queue {
    fd: libc::mqd_t,
    name: String,
}

impl Queue {
    /// Open an existing queue. Fails if it does not exist; never creates it.
    ///
    /// `read_only` is the default for the cutover: stage 6 receives and sends
    /// nothing, and opening the reply queue read-only makes that structural
    /// rather than a promise.
    pub fn open(name: &str, read_only: bool) -> Result<Queue, String> {
        let c = CString::new(name).map_err(|_| format!("{name}: not a valid queue name"))?;
        // Deliberately the 2-argument form: the 4-argument form is the one that
        // takes a mode and attributes, and it is only meaningful with O_CREAT.
        let fd = unsafe { libc::mq_open(c.as_ptr(), open_flags(read_only)) };
        if fd == -1 as libc::mqd_t {
            let e = std::io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::ENOENT) => format!(
                    "{name} does not exist -- /tuxedo creates it, so this means \
                     the vendor side is not running. Waiting is correct; creating it is not."
                ),
                _ => format!("{name}: {e}"),
            });
        }
        Ok(Queue { fd, name: name.to_string() })
    }

    /// Send one message. Stage 7a and later only; stage 6 must never reach this.
    ///
    /// `mq_send` takes the length to send and the queue refuses anything LARGER
    /// than its `msgsize` with EMSGSIZE -- it does not pad. The command queue's
    /// geometry is 404 (`ipc::COMMAND_LEN`) against the reply queue's 556, so
    /// sending a reply-sized buffer here fails, and the error says so rather than
    /// stalling.
    ///
    /// No timeout variant: `mq_send` on a queue that is not full returns at once,
    /// and a full command queue means `/tuxedo` has stopped draining it, which is a
    /// condition to report rather than to block on.
    pub fn send(&self, msg: &[u8]) -> Result<(), String> {
        let n = unsafe {
            libc::mq_send(self.fd, msg.as_ptr() as *const libc::c_char, msg.len(), 1)
        };
        if n == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        Err(match e.raw_os_error() {
            Some(libc::EMSGSIZE) => format!(
                "{}: refused a {}-byte message; the queue's msgsize is {} -- \
                 size the command from the queue, not from a constant",
                self.name,
                msg.len(),
                self.attr().map(|a| a.msgsize).unwrap_or(-1)
            ),
            Some(libc::EBADF) => format!(
                "{}: not open for writing -- Queue::open was given read_only = true",
                self.name
            ),
            Some(libc::EAGAIN) => format!(
                "{}: the queue is FULL; /tuxedo has stopped draining it",
                self.name
            ),
            _ => format!("{}: {e}", self.name),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn attr(&self) -> Result<Attr, String> {
        let mut a: libc::mq_attr = unsafe { std::mem::zeroed() };
        if unsafe { libc::mq_getattr(self.fd, &mut a) } == -1 {
            return Err(format!("{}: {}", self.name, std::io::Error::last_os_error()));
        }
        Ok(Attr {
            flags: a.mq_flags as i64,
            maxmsg: a.mq_maxmsg as i64,
            msgsize: a.mq_msgsize as i64,
            curmsgs: a.mq_curmsgs as i64,
        })
    }

    /// A buffer of exactly the size this queue demands.
    ///
    /// `mq_receive` returns `EMSGSIZE` for anything smaller, and a receive that
    /// always fails is indistinguishable from a panel that has gone quiet.
    pub fn buffer(&self) -> Result<Vec<u8>, String> {
        Ok(vec![0u8; self.attr()?.msgsize as usize])
    }

    /// Receive one message, waiting at most `timeout`.
    ///
    /// `Ok(None)` means the timeout expired with nothing waiting, which is the
    /// normal idle case and not an error. Distinguishing it from a real failure
    /// is what lets the caller loop without treating silence as breakage.
    pub fn receive(&self, buf: &mut [u8], timeout: Duration) -> Result<Option<usize>, String> {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) } == -1 {
            return Err(format!("clock_gettime: {}", std::io::Error::last_os_error()));
        }
        let total = ts.tv_nsec as u64 + timeout.subsec_nanos() as u64;
        ts.tv_sec += timeout.as_secs() as libc::time_t + (total / 1_000_000_000) as libc::time_t;
        ts.tv_nsec = (total % 1_000_000_000) as _;

        let mut prio: u32 = 0;
        let n = unsafe {
            libc::mq_timedreceive(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut prio,
                &ts,
            )
        };
        if n >= 0 {
            return Ok(Some(n as usize));
        }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ETIMEDOUT) => Ok(None),
            // EINTR is a signal, not a failure: the caller loops.
            Some(libc::EINTR) => Ok(None),
            Some(libc::EMSGSIZE) => Err(format!(
                "{}: buffer of {} is smaller than the queue's msgsize -- \
                 size it from mq_getattr, not from a constant",
                self.name,
                buf.len()
            )),
            _ => Err(format!("{}: {e}", self.name)),
        }
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        // close, never mq_unlink: the queue is /tuxedo's, and removing it would
        // outlive this process in the worst possible way.
        unsafe { libc::mq_close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_flags_can_never_create_a_queue() {
        // The whole of blocker B4 in one assertion. If someone adds O_CREAT
        // here to "make it work when the queue is missing", this fails, and
        // that is the entire point.
        for ro in [true, false] {
            let f = open_flags(ro);
            assert_eq!(f & libc::O_CREAT, 0, "O_CREAT must never be set");
            assert_eq!(f & libc::O_EXCL, 0);
            assert_ne!(f & libc::O_CLOEXEC, 0, "the deadman's exec is the close");
        }
        assert_ne!(open_flags(true) & libc::O_ACCMODE, libc::O_RDWR);
    }

    #[test]
    fn opening_a_queue_that_does_not_exist_fails_and_creates_nothing() {
        let name = format!("/tuxweb-absent-{}", std::process::id());
        let e = Queue::open(&name, true).unwrap_err();
        assert!(e.contains("does not exist"), "{e}");
        // and it must still not exist: a failed open that created the queue
        // would be the exact B4 failure, quietly
        let again = Queue::open(&name, true);
        assert!(again.is_err(), "the failed open must not have created it");
    }

    /// The syscall path, where POSIX message queues are actually available.
    ///
    /// Reports loudly when it cannot run rather than passing quietly: a skip
    /// that always skips is a test that cannot fail, which this repository has
    /// been bitten by twice.
    #[test]
    fn receive_round_trip_where_mq_is_available() {
        let name = CString::new(format!("/tuxweb-test-{}", std::process::id())).unwrap();
        let mut attr: libc::mq_attr = unsafe { std::mem::zeroed() };
        attr.mq_maxmsg = 4;
        attr.mq_msgsize = 556; // the panel's reply geometry
        let fd = unsafe {
            libc::mq_open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600 as libc::c_int,
                &attr,
            )
        };
        if fd == -1 as libc::mqd_t {
            eprintln!(
                "NOTE: POSIX mqueue unavailable here ({}); the syscall path is \
                 NOT covered by this run. It is covered on the build VM and the panel.",
                std::io::Error::last_os_error()
            );
            return;
        }

        let q = Queue::open(name.to_str().unwrap(), false).expect("open existing");
        let a = q.attr().expect("attr");
        assert_eq!(a.msgsize, 556, "attr must report the creator's geometry");
        assert_eq!(a.maxmsg, 4);
        assert_eq!(a.curmsgs, 0);

        // nothing waiting: a timeout is Ok(None), not an error
        let mut buf = q.buffer().expect("buffer");
        assert_eq!(buf.len(), 556, "the buffer is sized from the queue, not a constant");
        assert_eq!(q.receive(&mut buf, Duration::from_millis(50)).unwrap(), None);

        let msg = vec![0xABu8; 556];
        assert_eq!(
            unsafe { libc::mq_send(fd, msg.as_ptr() as *const libc::c_char, msg.len(), 1) },
            0
        );
        let n = q.receive(&mut buf, Duration::from_millis(500)).unwrap();
        assert_eq!(n, Some(556));
        assert_eq!(&buf[..], &msg[..]);

        // a short buffer must produce the explaining error, not a silent stall
        let mut small = vec![0u8; 8];
        let e = q.receive(&mut small, Duration::from_millis(50)).unwrap_err();
        assert!(e.contains("msgsize"), "{e}");

        drop(q);
        unsafe { libc::mq_unlink(name.as_ptr()) };
    }
}
