#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

static void r(const char *name, int rc)
{
    if (rc < 0)
        printf("  %-18s FAIL errno=%d (%s)\n", name, errno, strerror(errno));
    else
        printf("  %-18s ok\n", name);
}

int main(void)
{
    struct timespec ts;
    struct timeval  tv;
    fd_set fds;
    int s, rc;
    struct sockaddr_in a;

    printf("probe start\n");

    errno = 0;
    r("clock_gettime MON", clock_gettime(CLOCK_MONOTONIC, &ts));
    errno = 0;
    r("clock_gettime RT", clock_gettime(CLOCK_REALTIME, &ts));
    errno = 0;
    r("gettimeofday", gettimeofday(&tv, NULL));

    s = socket(AF_INET, SOCK_STREAM, 0);
    r("socket", s);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(0);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    r("bind", bind(s, (struct sockaddr *)&a, sizeof a));
    r("listen", listen(s, 5));

    FD_ZERO(&fds);
    FD_SET(s, &fds);
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    errno = 0;
    rc = select(s + 1, &fds, NULL, NULL, &tv);
    r("select timeout", rc);

    FD_ZERO(&fds);
    FD_SET(s, &fds);
    errno = 0;
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    rc = select(s + 1, &fds, NULL, NULL, &tv);
    r("select again", rc);

    r("fcntl", fcntl(s, F_GETFL, 0) < 0 ? -1 : 0);
    close(s);
    printf("probe end\n");
    return 0;
}
