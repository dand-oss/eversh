#include "zmosh-transcript.h"

#include <string.h>

void everudp_transcript_begin(everudp_transcript *transcript, uint8_t expected) {
    transcript->expected = expected;
    transcript->observed_len = 0;
    transcript->invalid = 0;
}

everudp_transcript_status everudp_transcript_finish(
    const everudp_transcript *transcript
) {
    if (transcript->invalid) {
        return EVERUDP_TRANSCRIPT_INVALID;
    }
    if (transcript->observed_len == 0) {
        return EVERUDP_TRANSCRIPT_WAITING;
    }
    if (transcript->observed_len == 1 &&
        transcript->observed[0] == transcript->expected) {
        return EVERUDP_TRANSCRIPT_MATCH;
    }
    return EVERUDP_TRANSCRIPT_INVALID;
}

everudp_transcript_status everudp_transcript_feed(
    everudp_transcript *transcript,
    const uint8_t *data,
    size_t len
) {
    if (transcript->invalid) {
        return EVERUDP_TRANSCRIPT_INVALID;
    }
    if (len > EVERUDP_TRANSCRIPT_CAP - transcript->observed_len) {
        transcript->invalid = 1;
        return EVERUDP_TRANSCRIPT_INVALID;
    }
    if (len != 0) {
        memcpy(transcript->observed + transcript->observed_len, data, len);
        transcript->observed_len += len;
    }
    if (everudp_transcript_finish(transcript) == EVERUDP_TRANSCRIPT_INVALID) {
        transcript->invalid = 1;
    }
    return everudp_transcript_finish(transcript);
}
