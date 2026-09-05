#include "zmosh/zmosh.h"

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
    uint64_t echo_ns;
    uint8_t expected;
    int connected;
} bench_ctx;

static void on_output(void *opaque, const uint8_t *data, uint32_t len) {
    bench_ctx *ctx = (bench_ctx *)opaque;
    if (ctx->echo_ns == 0 && memchr(data, ctx->expected, len) != NULL) {
        ctx->echo_ns = now_ns();
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
    bench_ctx ctx = {0};
    zmosh_status_t status = ZMOSH_OK;
    zmosh_session_t *session = zmosh_connect(
        host, port, key, 24, 80, on_output, on_state, on_end, &ctx, &status
    );
    if (session == NULL) {
        fprintf(stderr, "zmosh_connect failed: %d\n", (int)status);
        return 1;
    }
    /* Drain the initial restore/repaint stream until the session is quiet. */
    for (int i = 0; i < 100; ++i) {
        struct pollfd pfd = {.fd = zmosh_get_fd(session), .events = POLLIN};
        int ready = poll(&pfd, 1, 20);
        if (ready > 0) {
            zmosh_poll(session);
        } else if (ready == 0 && i > 10) {
            break;
        }
    }
    if (benchmark_barrier() != 0) {
        zmosh_disconnect(session);
        return 1;
    }
    printf("[");
    for (int trial = 0; trial < trials; ++trial) {
        const uint8_t input = (uint8_t)('a' + (trial % 26));
        ctx.echo_ns = 0;
        ctx.expected = input;
        ctx.send_ns = now_ns();
        zmosh_send_input(session, &input, 1);
        uint64_t deadline = now_ns() + 10000000000ull;
        while (now_ns() < deadline && ctx.echo_ns == 0) {
            struct pollfd pfd = {.fd = zmosh_get_fd(session), .events = POLLIN};
            poll(&pfd, 1, 20);
            zmosh_poll(session);
        }
        printf("%s%" PRIu64, trial ? "," : "",
               ctx.echo_ns ? (ctx.echo_ns - ctx.send_ns) / 1000 : 0);
        fflush(stdout);
        struct pollfd pfd = {.fd = zmosh_get_fd(session), .events = POLLIN};
        uint64_t quiet = now_ns() + (uint64_t)gap_ms * 1000000ull;
        while (now_ns() < quiet) {
            poll(&pfd, 1, 5);
            zmosh_poll(session);
        }
    }
    printf("]\n");
    zmosh_disconnect(session);
    return 0;
}
