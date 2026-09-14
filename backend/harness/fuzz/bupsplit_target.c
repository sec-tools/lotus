/*
 * libFuzzer/driver harness for bup's rolling-checksum splitter.
 *
 * Target: rollsum_sum() + the rollsum_roll macro in bupsplit.{c,h}, which
 * consume ARBITRARY UNTRUSTED byte buffers (backup stream content). We fuzz
 * with attacker-controlled length/content and several (ofs,len) framings to
 * probe for out-of-bounds reads or integer/window-index errors under ASan.
 *
 * Build is orchestrated by backend/fuzz_engine.py against the real bup sources
 * under data/e2e_targets/bup/lib/bup/.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "bupsplit.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* rollsum_sum takes a non-const buffer; copy to a heap block so ASan can
     * detect any read past the exact allocation size (redzone-tight). */
    uint8_t *buf = (uint8_t *)malloc(size ? size : 1);
    if (!buf) return 0;
    if (size) memcpy(buf, data, size);

    /* Framing 1: whole buffer. */
    volatile uint32_t s1 = rollsum_sum(buf, 0, size);
    (void)s1;

    /* Framing 2: attacker-chosen offset drawn from the input itself, clamped
     * to [0,size] so we exercise the ofs<len loop boundary without UB in the
     * harness (the point is to catch UB in the *target*). */
    if (size >= 2) {
        size_t ofs = (size_t)data[0] % (size + 1);
        volatile uint32_t s2 = rollsum_sum(buf, ofs, size);
        (void)s2;
    }

    /* Framing 3: incremental roll to exercise the window ring buffer. */
    Rollsum r;
    rollsum_init(&r);
    for (size_t i = 0; i < size; i++)
        rollsum_roll(&r, buf[i]);
    volatile uint32_t d = rollsum_digest(&r);
    (void)d;

    free(buf);
    return 0;
}
