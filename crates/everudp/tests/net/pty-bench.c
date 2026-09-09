#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

enum {
    STARTUP_QUIET_MS = 300,
    STARTUP_TIMEOUT_MS = 30000,
    OBSERVATION_TIMEOUT_MS = 10000,
};

struct observation {
    uint64_t elapsed_us;
    uint64_t send_ns;
    uint64_t accepted_ns;
};

/* Sample only outside the observation loop. Absolute monotonic timestamps
 * may be compared to another process only in the same boot/time namespace. */
struct clock_identity {
    char boot_id[37];
    uint64_t device;
    uint64_t inode;
};

static int clock_identity_read(struct clock_identity *identity) {
    FILE *stream = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (stream == NULL) return -1;
    char raw[38];
    size_t count = fread(raw, 1, sizeof(raw), stream);
    int failed = ferror(stream);
    if (fclose(stream) != 0 || failed || count != 37 || raw[36] != '\n') return -1;
    for (size_t i = 0; i < 36; ++i) {
        int separator = i == 8 || i == 13 || i == 18 || i == 23;
        if (separator ? raw[i] != '-' :
            !((raw[i] >= '0' && raw[i] <= '9') || (raw[i] >= 'a' && raw[i] <= 'f'))) return -1;
    }
    memcpy(identity->boot_id, raw, 36);
    identity->boot_id[36] = '\0';
    struct stat metadata;
    if (stat("/proc/self/ns/time", &metadata) != 0) return -1;
    identity->device = (uint64_t)metadata.st_dev;
    identity->inode = (uint64_t)metadata.st_ino;
    return 0;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static int parse_positive(const char *raw, const char *name) {
    char *end = NULL;
    errno = 0;
    long value = strtol(raw, &end, 10);
    if (errno != 0 || end == raw || *end != '\0' || value < 1 || value > 1000000) {
        fprintf(stderr, "invalid %s: %s\n", name, raw);
        exit(2);
    }
    return (int)value;
}

/* Out-of-band barriers exclude startup/warmup and child teardown from qdisc
 * snapshots. No helper process runs inside a timed observation. */
static int measurement_barrier(const char *phase) {
    const char *directory = getenv("PTY_BENCH_WINDOW_DIR");
    if (directory == NULL) return 0;
    char ready[4096], release[4096];
    int a = snprintf(ready, sizeof(ready), "%s/%s.ready", directory, phase);
    int b = snprintf(release, sizeof(release), "%s/%s.go", directory, phase);
    if (a < 0 || b < 0 || (size_t)a >= sizeof(ready) || (size_t)b >= sizeof(release)) return -1;
    int fd = open(ready, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) { perror("measurement barrier"); return -1; }
    close(fd);
    uint64_t deadline = now_ns() + UINT64_C(30000000000);
    while (access(release, F_OK) != 0) {
        if (errno != ENOENT || now_ns() >= deadline) {
            fprintf(stderr, "measurement barrier failed: %s\n", phase);
            return -1;
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
        nanosleep(&pause, NULL);
    }
    return 0;
}

static int child_alive(pid_t child) {
    int status = 0;
    pid_t result = waitpid(child, &status, WNOHANG);
    if (result == 0) {
        return 1;
    }
    if (result == child) {
        if (WIFEXITED(status)) {
            fprintf(stderr, "candidate exited early with status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "candidate exited early on signal %d\n", WTERMSIG(status));
        }
        return 0;
    }
    if (result < 0 && errno != EINTR) {
        perror("waitpid");
        return 0;
    }
    return 1;
}

static int poll_readable(int fd, int timeout_ms) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    for (;;) {
        int result = poll(&pfd, 1, timeout_ms);
        if (result >= 0) {
            if (result == 0) {
                return 0;
            }
            if ((pfd.revents & (POLLIN | POLLHUP)) != 0) {
                return 1;
            }
            if ((pfd.revents & (POLLERR | POLLNVAL)) != 0) {
                return -1;
            }
            return 0;
        }
        if (errno != EINTR) {
            perror("poll");
            return -1;
        }
    }
}

static ssize_t read_available(int fd, uint8_t *buffer, size_t capacity) {
    for (;;) {
        ssize_t count = read(fd, buffer, capacity);
        if (count >= 0) {
            return count;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        if (errno == EIO) {
            return -2;
        }
        perror("read PTY");
        return -1;
    }
}

static int write_byte(int fd, uint8_t byte) {
    for (;;) {
        ssize_t count = write(fd, &byte, 1);
        if (count == 1) {
            return 0;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = {.fd = fd, .events = POLLOUT};
            if (poll(&pfd, 1, 1000) >= 0) {
                continue;
            }
        }
        perror("write PTY");
        return -1;
    }
}

static int drain_until_quiet(int fd, pid_t child, int quiet_ms, int timeout_ms) {
    uint8_t buffer[16384];
    uint64_t deadline = now_ns() + (uint64_t)timeout_ms * UINT64_C(1000000);
    uint64_t quiet_deadline = now_ns() + (uint64_t)quiet_ms * UINT64_C(1000000);
    while (now_ns() < deadline) {
        uint64_t now = now_ns();
        if (now >= quiet_deadline) {
            return 0;
        }
        int remaining_ms = (int)((quiet_deadline - now + UINT64_C(999999)) / UINT64_C(1000000));
        int ready = poll_readable(fd, remaining_ms);
        if (ready < 0 || !child_alive(child)) {
            return -1;
        }
        if (ready == 0) {
            continue;
        }
        ssize_t count = read_available(fd, buffer, sizeof(buffer));
        if (count < 0) {
            return -1;
        }
        if (count > 0) {
            quiet_deadline = now_ns() + (uint64_t)quiet_ms * UINT64_C(1000000);
        }
    }
    fprintf(stderr, "candidate did not become quiet within %d ms\n", timeout_ms);
    return -1;
}

static int warm_up(int fd, pid_t child) {
    const uint8_t marker = 0x05;
    uint8_t buffer[16384];
    if (write_byte(fd, marker) != 0) {
        return -1;
    }
    uint64_t deadline = now_ns() + (uint64_t)STARTUP_TIMEOUT_MS * UINT64_C(1000000);
    int observed = 0;
    while (now_ns() < deadline && !observed) {
        int ready = poll_readable(fd, 100);
        if (ready < 0 || !child_alive(child)) {
            return -1;
        }
        if (ready == 0) {
            continue;
        }
        ssize_t count = read_available(fd, buffer, sizeof(buffer));
        if (count < 0) {
            return -1;
        }
        for (ssize_t index = 0; index < count; ++index) {
            if (buffer[index] == marker) {
                observed = 1;
            }
        }
    }
    if (!observed) {
        fprintf(stderr, "candidate did not echo the warm-up marker\n");
        return -1;
    }
    return drain_until_quiet(fd, child, STARTUP_QUIET_MS, STARTUP_TIMEOUT_MS);
}

static int observe_one(
    int fd,
    int sink_fd,
    pid_t child,
    uint8_t expected,
    int gap_ms,
    struct observation *sample
) {
    uint8_t buffer[16384];
    uint64_t started = now_ns();
    if (write_byte(fd, expected) != 0) {
        return -1;
    }
    uint64_t deadline = started + (uint64_t)OBSERVATION_TIMEOUT_MS * UINT64_C(1000000);
    uint64_t accepted = 0;
    while (now_ns() < deadline && accepted == 0) {
        int ready = poll_readable(fd, 100);
        if (ready < 0 || !child_alive(child)) {
            return -1;
        }
        if (ready == 0) {
            continue;
        }
        ssize_t count = read_available(fd, buffer, sizeof(buffer));
        if (count < 0) {
            return -1;
        }
        if (count == 0) {
            continue;
        }
        if (count != 1 || buffer[0] != expected) {
            fprintf(stderr, "wrong or extra transcript before acceptance: expected 0x%02x, got %zd bytes\n", expected, count);
            return -1;
        }
        if (write(sink_fd, buffer, 1) != 1) {
            perror("write output sink");
            return -1;
        }
        accepted = now_ns();
    }
    if (accepted == 0 || accepted <= started) {
        fprintf(stderr, "missing or non-positive observation for byte 0x%02x\n", expected);
        return -1;
    }

    uint64_t quiet_deadline = now_ns() + (uint64_t)gap_ms * UINT64_C(1000000);
    while (now_ns() < quiet_deadline) {
        uint64_t now = now_ns();
        int remaining_ms = (int)((quiet_deadline - now + UINT64_C(999999)) / UINT64_C(1000000));
        int ready = poll_readable(fd, remaining_ms);
        if (ready < 0 || !child_alive(child)) {
            return -1;
        }
        if (ready == 0) {
            continue;
        }
        ssize_t count = read_available(fd, buffer, sizeof(buffer));
        if (count < 0) {
            return -1;
        }
        if (count > 0) {
            fprintf(stderr, "extra transcript after accepted byte 0x%02x: %zd bytes\n", expected, count);
            return -1;
        }
    }
    /* Save already-sampled boundaries after the quiet interval: no extra
     * timestamp calls or diagnostic I/O enter the timed send/accept path. */
    sample->elapsed_us = (accepted - started + UINT64_C(999)) / UINT64_C(1000);
    sample->send_ns = started;
    sample->accepted_ns = accepted;
    return 0;
}

static void stop_child(pid_t child) {
    if (child <= 0) {
        return;
    }
    kill(-child, SIGTERM);
    for (int attempt = 0; attempt < 60; ++attempt) {
        int status = 0;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child || (result < 0 && errno == ECHILD)) {
            return;
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 50000000};
        nanosleep(&pause, NULL);
    }
    kill(-child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
}

int main(int argc, char **argv) {
    if (argc < 7 || strcmp(argv[5], "--") != 0) {
        fprintf(stderr, "usage: pty-bench TRIALS GAP_MS RESULT_JSON STDERR_LOG -- COMMAND [ARG...]\n");
        return 2;
    }
    int trials = parse_positive(argv[1], "trials");
    int gap_ms = parse_positive(argv[2], "gap_ms");
    const char *result_path = argv[3];
    const char *stderr_path = argv[4];
    char **command = &argv[6];

    struct clock_identity clock_start;
    if (clock_identity_read(&clock_start) != 0) {
        fprintf(stderr, "cannot establish benchmark clock identity\n");
        return 1;
    }

    struct observation *samples = calloc((size_t)trials, sizeof(*samples));
    if (samples == NULL) {
        perror("calloc samples");
        return 1;
    }
    int sink_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (sink_fd < 0) {
        perror("open output sink");
        free(samples);
        return 1;
    }

    int master = -1;
    int slave = -1;
    struct winsize size = {.ws_row = 24, .ws_col = 80};
    struct termios attributes;
    if (openpty(&master, &slave, NULL, NULL, &size) != 0 || tcgetattr(slave, &attributes) != 0) {
        perror("openpty/tcgetattr");
        close(sink_fd);
        free(samples);
        return 1;
    }
    cfmakeraw(&attributes);
    if (tcsetattr(slave, TCSANOW, &attributes) != 0) {
        perror("tcsetattr");
        close(master);
        close(slave);
        close(sink_fd);
        free(samples);
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        close(master);
        close(slave);
        close(sink_fd);
        free(samples);
        return 1;
    }
    if (child == 0) {
        if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) < 0) {
            _exit(126);
        }
        int err_fd = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (err_fd < 0 || dup2(slave, STDIN_FILENO) < 0 || dup2(slave, STDOUT_FILENO) < 0 || dup2(err_fd, STDERR_FILENO) < 0) {
            _exit(126);
        }
        close(err_fd);
        close(master);
        if (slave > STDERR_FILENO) {
            close(slave);
        }
        execvp(command[0], command);
        _exit(127);
    }

    close(slave);
    int flags = fcntl(master, F_GETFL, 0);
    if (flags < 0 || fcntl(master, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("set PTY nonblocking");
        stop_child(child);
        close(master);
        close(sink_fd);
        free(samples);
        return 1;
    }

    int result = 1;
    if (drain_until_quiet(master, child, STARTUP_QUIET_MS, STARTUP_TIMEOUT_MS) != 0 ||
        warm_up(master, child) != 0 || measurement_barrier("start") != 0) {
        goto done;
    }

    static const uint8_t alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int trial = 0; trial < trials; ++trial) {
        uint8_t expected = alphabet[(size_t)trial % (sizeof(alphabet) - 1)];
        if (observe_one(master, sink_fd, child, expected, gap_ms, &samples[trial]) != 0) {
            fprintf(stderr, "observation %d/%d failed\n", trial + 1, trials);
            goto done;
        }
    }

    if (measurement_barrier("finish") != 0) goto done;
    struct clock_identity clock_end;
    if (clock_identity_read(&clock_end) != 0 ||
        strcmp(clock_start.boot_id, clock_end.boot_id) != 0 ||
        clock_start.device != clock_end.device || clock_start.inode != clock_end.inode) {
        fprintf(stderr, "benchmark clock identity changed or unavailable\n");
        goto done;
    }
    FILE *stream = fopen(result_path, "w");
    if (stream == NULL) {
        perror("open result JSON");
        goto done;
    }
    fprintf(stream, "{\"schema_version\":1,\"trials\":%d,\"gap_ms\":%d,\"transcript_failures\":0,\"samples_us\":[", trials, gap_ms);
    for (int trial = 0; trial < trials; ++trial) {
        fprintf(stream, "%s%" PRIu64, trial == 0 ? "" : ",", samples[trial].elapsed_us);
    }
    fprintf(stream, "],\"public_clock\":\"CLOCK_MONOTONIC; local host and time namespace only\",\"clock_identity\":{\"boot_id\":\"%s\",\"time_namespace_dev\":%" PRIu64 ",\"time_namespace_ino\":%" PRIu64 "},\"benchmark_pid\":%ld,\"public_boundaries\":[",
            clock_start.boot_id, clock_start.device, clock_start.inode, (long)getpid());
    for (int trial = 0; trial < trials; ++trial) {
        fprintf(stream, "%s{\"trial\":%d,\"send_ns\":%" PRIu64 ",\"accepted_ns\":%" PRIu64 "}",
                trial == 0 ? "" : ",", trial, samples[trial].send_ns, samples[trial].accepted_ns);
    }
    if (fprintf(stream, "]}\n") < 0 || fclose(stream) != 0) {
        perror("write result JSON");
        goto done;
    }
    result = 0;

done:
    stop_child(child);
    close(master);
    close(sink_fd);
    free(samples);
    return result;
}
