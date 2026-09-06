/* panelstated: expose the Tuxedo's ECP link state over HTTP.
 *
 * The only way a client learns the panel-to-VISTA link is down is field 2 of a
 * push frame reading -1. GetSecurityStatus reads the same ECP-fed cache and
 * keeps answering the last thing in it, so link state is knowable through
 * exactly one transport. A client whose stream drops cannot tell "panel
 * healthy, stream dropped" from "panel still blind", and has to fail closed.
 *
 * This holds the push stream locally and serves what it learns over HTTP, so a
 * client can ask on a transport independent of its own stream:
 *
 *     GET /  ->  {"talking":true,"code":1,"status":"Ready To Arm",
 *                 "age_s":4,"stream":"up","frames":37,
 *                 "raw":"0:21:1:fe:þ1Ready To Arm:2"}
 *
 * The raw frame is served verbatim so a consumer can run one decoder rather
 * than trusting the fields picked out here.
 *
 * It patches nothing. It is a reader of the same stream everything else uses.
 *
 * Build:  musl-gcc -Os -static -o panelstated panelstated.c
 * Run:    panelstated [listen_port] [panel_host]
 *         defaults 8088 and 127.0.0.1
 *
 * The host is settable so this can be tested off-panel, against the real panel
 * over the network, before anything is installed on the device.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define PANEL_PORT 80
#define DEFAULT_LISTEN 8088
#define BUFSZ 8192

static int   g_code   = -1;          /* field 2 of the last 0:21: frame */
static char  g_status[64] = "";      /* the display text from that frame */
static time_t g_seen  = 0;           /* when we last parsed a frame */
static long  g_frames = 0;
static char  g_raw[192] = "";        /* the last status frame, verbatim */
static int   g_stream_up = 0;

static const char *g_host = "127.0.0.1";

static int connect_stream(void)
{
    struct sockaddr_in a;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    const char *req =
        "GET /SimpleDebugger.interface/G. HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\nAccept: */*\r\n\r\n";
    if (s < 0)
        return -1;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(PANEL_PORT);
    a.sin_addr.s_addr = inet_addr(g_host);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
        close(s);
        return -1;
    }
    if (write(s, req, strlen(req)) < 0) {
        close(s);
        return -1;
    }
    return s;
}

/* Frames look like  0:21:<code>:<flag>:<raw><colour><text>:<colour>
 * We want <code>, which is -1 whenever PanelIsTalking() is false, and the
 * trailing display text. Everything is latin-1; the raw flag byte can be any
 * value, so we scan bytewise rather than treating it as a C string. */
static void parse(const char *buf, int n)
{
    int i;
    for (i = 0; i + 6 < n; i++) {
        if (memcmp(buf + i, "0:21:", 5) != 0)
            continue;
        {
            const char *p = buf + i + 5;
            const char *end = buf + n;
            char num[12];
            int k = 0;
            if (*p == '-' && k < 11)
                num[k++] = *p++;
            while (p < end && *p >= '0' && *p <= '9' && k < 11)
                num[k++] = *p++;
            if (k == 0 || p >= end || *p != ':')
                continue;
            num[k] = 0;
            g_code = atoi(num);
            /* the display text is the last colon-delimited field but one */
            {
                const char *q = p;
                const char *txt = NULL;
                int fields = 0;
                while (q < end && *q != '\r' && *q != '"') {
                    if (*q == ':') {
                        fields++;
                        /* 0:21:<code>:<flag>:<raw><colour><text>:<colour>
                         * counting from just after <code>, the second colon
                         * opens the text field. Counting to three lands on the
                         * trailing colour instead, which is how this first came
                         * back empty. */
                        if (fields == 2)
                            txt = q + 1;
                    }
                    q++;
                }
                if (txt && txt < q) {
                    int len = 0;
                    const char *t = txt;
                    /* skip the raw flag byte and the colour digit */
                    if (t < q && (unsigned char)*t > 0x7e)
                        t++;
                    if (t < q && *t >= '0' && *t <= '9')
                        t++;
                    while (t + len < q && *(t + len) != ':' && len < 63)
                        len++;
                    memcpy(g_status, t, len);
                    g_status[len] = 0;
                }
            }
            /* Keep the frame verbatim too, so a consumer can run one decoder
             * rather than trusting the fields picked out here. Non-printable
             * bytes are escaped: the state flag is a raw byte and the payload
             * is latin-1, so this must survive JSON. */
            {
                const char *b = buf + i;
                const char *stop = b;
                int o = 0;
                while (stop < end && *stop != '"' && *stop != 0x0d)
                    stop++;
                while (b < stop && o < (int)sizeof g_raw - 7) {
                    unsigned char ch = (unsigned char)*b++;
                    if (ch == '"' || ch == 0x5c) {
                        g_raw[o++] = 0x5c;
                        g_raw[o++] = ch;
                    } else if (ch < 0x20 || ch > 0x7e) {
                        o += snprintf(g_raw + o, 7, "%cu%04x", 0x5c, ch);
                    } else {
                        g_raw[o++] = ch;
                    }
                }
                g_raw[o] = 0;
            }
            g_seen = time(NULL);
            g_frames++;
        }
    }
}

static void serve(int c)
{
    char req[512], body[600], out[1200];
    int n, age;
    n = read(c, req, sizeof req - 1);
    if (n < 0)
        n = 0;
    req[n] = 0;
    age = g_seen ? (int)(time(NULL) - g_seen) : -1;
    snprintf(body, sizeof body,
             "{\"talking\":%s,\"code\":%d,\"status\":\"%s\","
             "\"age_s\":%d,\"stream\":\"%s\",\"frames\":%ld,\"raw\":\"%s\"}\n",
             (g_code >= 0 && g_seen) ? "true" : "false",
             g_code, g_status, age, g_stream_up ? "up" : "down",
             g_frames, g_raw);
    snprintf(out, sizeof out,
             "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
             "Content-Length: %d\r\nConnection: close\r\n"
             "Cache-Control: no-store\r\n\r\n%s",
             (int)strlen(body), body);
    if (write(c, out, strlen(out)) < 0)
        ;                       /* client hung up; nothing useful to do */
    close(c);
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : DEFAULT_LISTEN;
    if (argc > 2)
        g_host = argv[2];
    int lsock, stream = -1, one = 1;
    struct sockaddr_in la;
    time_t next_try = 0;

    signal(SIGPIPE, SIG_IGN);

    lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0)
        return 1;
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_port = htons(port);
    la.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(lsock, (struct sockaddr *)&la, sizeof la) < 0) {
        fprintf(stderr, "bind %d: %s\n", port, strerror(errno));
        return 1;
    }
    listen(lsock, 8);

    for (;;) {
        fd_set fds;
        struct timeval tv;
        int maxfd = lsock;

        if (stream < 0 && time(NULL) >= next_try) {
            stream = connect_stream();
            g_stream_up = stream >= 0;
            if (stream < 0)
                next_try = time(NULL) + 10;
        }
        FD_ZERO(&fds);
        FD_SET(lsock, &fds);
        if (stream >= 0) {
            FD_SET(stream, &fds);
            if (stream > maxfd)
                maxfd = stream;
        }
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        if (select(maxfd + 1, &fds, NULL, NULL, &tv) < 0) {
            if (errno == EINTR)
                continue;
            return 1;
        }
        if (stream >= 0 && FD_ISSET(stream, &fds)) {
            char buf[BUFSZ];
            int n = read(stream, buf, sizeof buf);
            if (n <= 0) {
                close(stream);
                stream = -1;
                g_stream_up = 0;
                next_try = time(NULL) + 2;
            } else {
                parse(buf, n);
            }
        }
        if (FD_ISSET(lsock, &fds)) {
            int c = accept(lsock, NULL, NULL);
            if (c >= 0)
                serve(c);
        }
    }
}
