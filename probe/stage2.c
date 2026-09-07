/* stage2: the on-panel measurements WEBSERVER-REPLACEMENT.md stage 2 asks for.
 *
 *   stage2
 *
 * Two things, both read-only:
 *
 *  1. Queue geometry from mq_getattr rather than from the binaries. The sizes
 *     in the docs were READ out of Barracuda and /tuxedo; this MEASURES them.
 *     mq_getattr does not consume a message, and the queues are opened
 *     O_RDONLY|O_NONBLOCK so nothing can block and nothing is received.
 *     /dev/mq on 2.6.31 exposes only QSIZE/NOTIFY/SIGNO/NOTIFY_PID, which is
 *     why this needs a binary at all.
 *
 *  2. What /dev/random will actually give you, and at what rate. The cert
 *     design rests on the claim that this pool cannot produce a key. Reading
 *     it BLOCKING would hang the probe for an unbounded time -- which is the
 *     finding, but an unusable way to get it -- so it is opened O_NONBLOCK and
 *     drained against a deadline. entropy_avail is sampled either side.
 *
 * Nothing here writes to the pool. seedrng is deliberately NOT run from this
 * program: it mutates kernel state and belongs in its own deliberate step.
 *
 *   /opt/musl-armel/bin/musl-gcc -Os -static -o stage2 stage2.c   # on the VM
 */
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static const char *QUEUES[] = {
    "/Q_ServCmdRcver",          /* Barracuda -> tuxedo, the write path  */
    "/Q_ServCmdTrsmtr",         /* tuxedo -> Barracuda, the read path   */
    "/mqUI_Input_Queue",        /* intra-tuxedo                          */
    "/g_mqSupervisionThreadIn", /* supervis                              */
    "/mq_TuxAppVidRecEvent",
    "/mq_VidRecWebAppEvent",
    NULL
};

static long read_long(const char *path)
{
    char buf[64];
    long v = -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n > 0) {
        buf[n] = 0;
        v = strtol(buf, NULL, 10);
    }
    close(fd);
    return v;
}

static double now(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

static void queues(void)
{
    printf("== message queue geometry (mq_getattr, nothing consumed) ==\n");
    printf("%-26s %8s %8s %8s %s\n", "queue", "maxmsg", "msgsize", "curmsgs", "flags");
    for (int i = 0; QUEUES[i]; i++) {
        mqd_t q = mq_open(QUEUES[i], O_RDONLY | O_NONBLOCK);
        if (q == (mqd_t)-1) {
            printf("%-26s   %s\n", QUEUES[i], strerror(errno));
            continue;
        }
        struct mq_attr a;
        if (mq_getattr(q, &a) == 0)
            printf("%-26s %8ld %8ld %8ld 0x%lx\n", QUEUES[i],
                   a.mq_maxmsg, a.mq_msgsize, a.mq_curmsgs, a.mq_flags);
        else
            printf("%-26s   mq_getattr: %s\n", QUEUES[i], strerror(errno));
        mq_close(q);
    }
}

static void entropy(int seconds)
{
    printf("\n== /dev/random, non-blocking, %d second deadline ==\n", seconds);
    long before = read_long("/proc/sys/kernel/random/entropy_avail");
    long poolsz = read_long("/proc/sys/kernel/random/poolsize");
    printf("entropy_avail before %ld, poolsize %ld\n", before, poolsz);

    int fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        printf("open /dev/random: %s\n", strerror(errno));
        return;
    }
    unsigned char buf[32];
    size_t got = 0;
    int eagain = 0;
    double t0 = now(), t_first_short = -1;
    while (got < sizeof buf && now() - t0 < seconds) {
        ssize_t n = read(fd, buf + got, sizeof buf - got);
        if (n > 0) {
            got += (size_t)n;
        } else if (n < 0 && errno == EAGAIN) {
            if (t_first_short < 0)
                t_first_short = now() - t0;
            eagain++;
            usleep(200000);
        } else {
            printf("read: %s\n", n == 0 ? "EOF" : strerror(errno));
            break;
        }
    }
    double dt = now() - t0;
    close(fd);

    long after = read_long("/proc/sys/kernel/random/entropy_avail");
    printf("got %u of 32 bytes in %.1fs (%d EAGAIN", (unsigned)got, dt, eagain);
    if (t_first_short >= 0)
        printf(", first at %.1fs", t_first_short);
    printf(")\n");
    printf("entropy_avail after %ld (delta %ld)\n", after, after - before);
    if (got < sizeof buf)
        printf("VERDICT: this pool cannot produce 256 bits on demand\n");
    else
        printf("VERDICT: 256 bits obtained in %.1fs -- re-check the cert design\n", dt);
}

static void urandom_control(void)
{
    printf("\n== /dev/urandom, as a control ==\n");
    unsigned char buf[32];
    double t0 = now();
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        printf("open: %s\n", strerror(errno));
        return;
    }
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    printf("read %zd bytes in %.3fs -- so the probe itself is not the slow part\n",
           n, now() - t0);
}

int main(void)
{
    queues();
    entropy(30);
    urandom_control();
    return 0;
}
