#define _POSIX_C_SOURCE 200809L

#include "zmosh/zmosh.h"
#include "zmosh-transcript.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

typedef struct {
    uint64_t send_ns;
    uint64_t accepted_ns;
    everudp_transcript transcript;
    int collecting;
    int sink_fd;
    int sink_error;
} bench_ctx;

static int write_all(int fd, const uint8_t *data, uint32_t len) {
    uint32_t written = 0;
    while (written < len) {
        ssize_t count = write(fd, data + written, len - written);
        if (count > 0) {
            written += (uint32_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static void on_output(void *opaque, const uint8_t *data, uint32_t len) {
    bench_ctx *ctx = (bench_ctx *)opaque;
    if (write_all(ctx->sink_fd, data, len) != 0) {
        ctx->sink_error = 1;
        return;
    }
    if (!ctx->collecting) {
        return;
    }
    everudp_transcript_status before = everudp_transcript_finish(&ctx->transcript);
    everudp_transcript_status after =
        everudp_transcript_feed(&ctx->transcript, data, len);
    if (before == EVERUDP_TRANSCRIPT_WAITING &&
        after == EVERUDP_TRANSCRIPT_MATCH) {
        ctx->accepted_ns = now_ns();
    }
}

static void on_state(void *opaque, zmosh_state_t state) {
    (void)opaque;
    (void)state;
}

static void on_end(void *opaque) {
    (void)opaque;
}

static int benchmark_barrier(void) {
    const char *ready = getenv("EVERUDP_BENCH_READY_FILE");
    const char *go = getenv("EVERUDP_BENCH_GO_FILE");
    if (ready == NULL && go == NULL) {
        return 0;
    }
    if (ready == NULL || go == NULL) {
        fprintf(stderr, "benchmark barrier requires both ready and go files\n");
        return -1;
    }
    FILE *stream = fopen(ready, "w");
    if (stream == NULL) {
        perror("write benchmark ready file");
        return -1;
    }
    fputs("ready\n", stream);
    if (fclose(stream) != 0) {
        perror("close benchmark ready file");
        return -1;
    }
    const uint64_t deadline = now_ns() + 60000000000ull;
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    while (access(go, F_OK) != 0) {
        if (now_ns() >= deadline) {
            fprintf(stderr, "benchmark barrier timed out\n");
            return -1;
        }
        nanosleep(&pause, NULL);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: zmosh-bench HOST PORT KEY TRIALS GAP_MS\n");
        return 2;
    }
    const char *host = argv[1];
    uint16_t port = (uint16_t)strtoul(argv[2], NULL, 10);
    const char *key = argv[3];
    if (strcmp(key, "-") == 0) {
        key = getenv("ZMOSH_BENCH_KEY");
    }
    if (key == NULL || key[0] == '\0') {
        fprintf(stderr, "missing zmosh benchmark key\n");
        return 2;
    }
    int trials = atoi(argv[4]);
    int gap_ms = atoi(argv[5]);
    if (trials < 1 || gap_ms < 1) {
        fprintf(stderr, "trials and gap must be positive\n");
        return 2;
    }
    int sink_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (sink_fd < 0) {
        perror("open benchmark output sink");
        return 1;
    }
    bench_ctx ctx = {.sink_fd = sink_fd};
    zmosh_status_t status = ZMOSH_OK;
    zmosh_session_t *session = zmosh_connect(
        host, port, key, 24, 80, on_output, on_state, on_end, &ctx, &status
    );
    if (session == NULL) {
        fprintf(stderr, "zmosh_connect failed: %d\n", (int)status);
        close(sink_fd);
        return 1;
    }
    /* Drain the initial restore/repaint stream until the session is quiet. */
    for (int i = 0; i < 100; ++i) {
        struct pollfd pfd = {.fd = zmosh_get_fd(session), .events = POLLIN};
        int ready = poll(&pfd, 1, 20);
        if (ready > 0) {
            zmosh_poll(session);
            if (ctx.sink_error) {
                fprintf(stderr, "benchmark output sink failed\n");
                zmosh_disconnect(session);
                close(sink_fd);
                return 1;
            }
        } else if (ready == 0 && i > 10) {
            break;
        }
    }
    if (benchmark_barrier() != 0) {
        zmosh_disconnect(session);
        close(sink_fd);
        return 1;
    }
    printf("[");
    for (int trial = 0; trial < trials; ++trial) {
        const uint8_t input = (uint8_t)('a' + (trial % 26));
        ctx.accepted_ns = 0;
        ctx.sink_error = 0;
        everudp_transcript_begin(&ctx.transcript, input);
        ctx.collecting = 1;
        ctx.send_ns = now_ns();
        status = zmosh_send_input(session, &input, 1);
        if (status != ZMOSH_OK) {
            fprintf(stderr, "zmosh_send_input failed: %d\n", (int)status);
            zmosh_disconnect(session);
            close(sink_fd);
            return 1;
        }
        uint64_t deadline = now_ns() + 10000000000ull;
        while (now_ns() < deadline && ctx.accepted_ns == 0 &&
               everudp_transcript_finish(&ctx.transcript) !=
                   EVERUDP_TRANSCRIPT_INVALID &&
               !ctx.sink_error) {
            struct pollfd pfd = {.fd = zmosh_get_fd(session), .events = POLLIN};
            poll(&pfd, 1, 20);
            zmosh_poll(session);
        }
        if (ctx.accepted_ns == 0 || ctx.sink_error ||
            everudp_transcript_finish(&ctx.transcript) !=
                EVERUDP_TRANSCRIPT_MATCH) {
            fprintf(stderr, "trial %d produced no exact transcript\n", trial);
            zmosh_disconnect(session);
            close(sink_fd);
            return 1;
        }
        struct pollfd pfd = {.fd = zmosh_get_fd(session), .events = POLLIN};
        uint64_t quiet = now_ns() + (uint64_t)gap_ms * 1000000ull;
        while (now_ns() < quiet) {
            poll(&pfd, 1, 5);
            zmosh_poll(session);
        }
        ctx.collecting = 0;
        if (ctx.sink_error ||
            everudp_transcript_finish(&ctx.transcript) !=
                EVERUDP_TRANSCRIPT_MATCH) {
            fprintf(stderr, "trial %d produced extra or invalid output\n", trial);
            zmosh_disconnect(session);
            close(sink_fd);
            return 1;
        }
        printf("%s%" PRIu64, trial ? "," : "",
               (ctx.accepted_ns - ctx.send_ns) / 1000);
        fflush(stdout);
    }
    printf("]\n");
    zmosh_disconnect(session);
    close(sink_fd);
    return 0;
}
