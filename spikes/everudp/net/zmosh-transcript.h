#ifndef EVERUDP_ZMOSH_TRANSCRIPT_H
#define EVERUDP_ZMOSH_TRANSCRIPT_H

#include <stddef.h>
#include <stdint.h>

enum { EVERUDP_TRANSCRIPT_CAP = 4096 };

typedef enum {
    EVERUDP_TRANSCRIPT_WAITING = 0,
    EVERUDP_TRANSCRIPT_MATCH = 1,
    EVERUDP_TRANSCRIPT_INVALID = 2,
} everudp_transcript_status;

typedef struct {
    uint8_t expected;
    uint8_t observed[EVERUDP_TRANSCRIPT_CAP];
    size_t observed_len;
    int invalid;
} everudp_transcript;

void everudp_transcript_begin(everudp_transcript *transcript, uint8_t expected);

everudp_transcript_status everudp_transcript_feed(
    everudp_transcript *transcript,
    const uint8_t *data,
    size_t len
);

everudp_transcript_status everudp_transcript_finish(
    const everudp_transcript *transcript
);

#endif
