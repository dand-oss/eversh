#define _DEFAULT_SOURCE

#include <errno.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>

static int write_all(int fd, const uint8_t *data, size_t len) {
    size_t written = 0;
    while (written < len) {
        ssize_t count = write(fd, data + written, len - written);
        if (count > 0) {
            written += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

int main(void) {
    struct termios original;
    if (tcgetattr(STDIN_FILENO, &original) != 0) {
        return 1;
    }
    struct termios raw = original;
    cfmakeraw(&raw);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) {
        return 1;
    }

    uint8_t buffer[16384];
    for (;;) {
        ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
        if (count > 0) {
            if (write_all(STDOUT_FILENO, buffer, (size_t)count) != 0) {
                return 1;
            }
            continue;
        }
        if (count == 0) {
            (void)tcsetattr(STDIN_FILENO, TCSANOW, &original);
            return 0;
        }
        if (errno != EINTR) {
            (void)tcsetattr(STDIN_FILENO, TCSANOW, &original);
            return 1;
        }
    }
}
