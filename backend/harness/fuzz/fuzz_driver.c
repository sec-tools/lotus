/*
 * Dependency-free fuzzing driver.
 *
 * Wraps a standard `LLVMFuzzerTestOneInput(const uint8_t*, size_t)` harness so
 * it can run WITHOUT the libFuzzer runtime (which Apple CLT clang / stock gcc
 * lack). When compiled with clang `-fsanitize=fuzzer` this file is omitted and
 * libFuzzer drives coverage-guided fuzzing instead; otherwise this provides a
 * seed-based random-mutation loop run under -fsanitize=address,undefined so
 * memory-safety violations still abort with a saved reproducer.
 *
 * The current input is persisted to $FUZZ_CRASH_FILE before every call, so if
 * a sanitizer aborts the process the file holds the exact crashing bytes.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#ifndef FUZZ_MAX_LEN
#define FUZZ_MAX_LEN 4096
#endif

static const char *crash_file(void) {
    const char *p = getenv("FUZZ_CRASH_FILE");
    return p ? p : "fuzz-crash-input";
}

static void save_input(const uint8_t *buf, size_t n) {
    FILE *f = fopen(crash_file(), "wb");
    if (!f) return;
    fwrite(buf, 1, n, f);
    fclose(f);
}

static size_t mutate(uint8_t *buf, size_t n, size_t cap) {
    int ops = 1 + (rand() % 6);
    for (int i = 0; i < ops; i++) {
        int kind = rand() % 4;
        if (kind == 0 && n > 0) {                 /* flip a byte */
            buf[rand() % n] ^= (uint8_t)(1 << (rand() % 8));
        } else if (kind == 1 && n < cap) {        /* insert byte */
            size_t pos = n ? (size_t)(rand() % n) : 0;
            memmove(buf + pos + 1, buf + pos, n - pos);
            buf[pos] = (uint8_t)(rand() & 0xff);
            n++;
        } else if (kind == 2 && n > 0) {          /* delete byte */
            size_t pos = (size_t)(rand() % n);
            memmove(buf + pos, buf + pos + 1, n - pos - 1);
            n--;
        } else if (kind == 3 && n < cap) {        /* append random */
            buf[n++] = (uint8_t)(rand() & 0xff);
        }
    }
    return n;
}

int main(int argc, char **argv) {
    unsigned seed = (unsigned)(argc > 1 ? atoi(argv[1]) : (int)time(NULL));
    long max_seconds = argc > 2 ? atol(argv[2]) : 15;
    long max_iters = argc > 3 ? atol(argv[3]) : 5000000L;
    srand(seed);

    uint8_t buf[FUZZ_MAX_LEN];
    time_t start = time(NULL);
    long iters = 0;

    /* A few structured seeds; the mutator explores from here. */
    static const char *seeds[] = { "", "A", "bup", "\x00\x00\x00\x00",
                                   "the quick brown fox jumps over 0123456789" };
    for (long i = 0; i < max_iters; i++) {
        const char *s = seeds[i % (long)(sizeof(seeds) / sizeof(seeds[0]))];
        size_t n = strlen(s);
        if (n > FUZZ_MAX_LEN) n = FUZZ_MAX_LEN;
        memcpy(buf, s, n);
        n = mutate(buf, n, FUZZ_MAX_LEN);
        save_input(buf, n);
        LLVMFuzzerTestOneInput(buf, n);   /* ASan/UBSan abort => reproducer saved */
        iters++;
        if ((i & 0x3fff) == 0 && (time(NULL) - start) >= max_seconds) break;
    }
    fprintf(stderr, "fuzz-driver: completed %ld iterations, seed=%u, no crash\n",
            iters, seed);
    return 0;
}
