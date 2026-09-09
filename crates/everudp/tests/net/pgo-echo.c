#define _DEFAULT_SOURCE
#include <errno.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>

static int put_all(int fd, const uint8_t *p, size_t n) {
    while (n) {
        ssize_t got = write(fd, p, n);
        if (got > 0) { p += got; n -= (size_t)got; }
        else if (got < 0 && errno == EINTR) continue;
        else return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char *end = NULL;
    unsigned long long budget = strtoull(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || budget == 0 || budget > 100000000ULL) return 2;
    struct termios saved;
    if (tcgetattr(STDIN_FILENO, &saved) != 0) return 1;
    struct termios raw = saved;
    cfmakeraw(&raw);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) return 1;
    static const uint8_t ready[] = "EVERUDP-PGO-ECHO-READY\n";
    if (put_all(STDOUT_FILENO, ready, sizeof(ready) - 1) != 0) return 1;
    uint8_t buffer[16384];
    while (budget != 0) {
        size_t want = budget < sizeof(buffer) ? (size_t)budget : sizeof(buffer);
        ssize_t got = read(STDIN_FILENO, buffer, want);
        if (got > 0) { if (put_all(STDOUT_FILENO, buffer, (size_t)got) != 0) return 1; budget -= (unsigned long long)got; continue; }
        if (got < 0 && errno == EINTR) continue;
        if (got == 0 || (got < 0 && errno == EIO)) {
            (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved);
            return 1;
        }
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved);
        return 1;
    }
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved);
    return 0;
}
