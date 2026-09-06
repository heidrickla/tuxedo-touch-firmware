/* peek: read words out of a running process on the panel.
 *
 * /proc/<pid>/mem refuses a plain read on 2.6.31 and there is no debugger on
 * the device. ptrace is right there in the kernel, so this is thirty lines
 * rather than a wall.
 *
 *     peek <pid> <hex addr> [count]
 *
 * Attaches, waits for the stop, PEEKDATAs, detaches. Read-only: it never
 * writes to the target and always detaches, including on error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
    long pid, addr, i, n = 1, w;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid> <hexaddr> [words]\n", argv[0]);
        return 2;
    }
    pid  = strtol(argv[1], NULL, 0);
    addr = strtol(argv[2], NULL, 16);
    if (argc > 3)
        n = strtol(argv[3], NULL, 0);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        fprintf(stderr, "attach %ld: %s\n", pid, strerror(errno));
        return 1;
    }
    waitpid(pid, NULL, 0);

    for (i = 0; i < n; i++) {
        errno = 0;
        w = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i * 4), NULL);
        if (errno) {
            fprintf(stderr, "peek %lx: %s\n", addr + i * 4, strerror(errno));
            break;
        }
        printf("%08lx  %08lx  bytes %02lx %02lx %02lx %02lx\n",
               addr + i * 4, (unsigned long)w,
               (unsigned long)(w        & 0xff), (unsigned long)((w >>  8) & 0xff),
               (unsigned long)((w >> 16) & 0xff), (unsigned long)((w >> 24) & 0xff));
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
