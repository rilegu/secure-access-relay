/*
 * Tests for the parts of sardiag that can corrupt memory.
 *
 * The collectors are Windows-specific and read live system state, so they are
 * exercised by the Go side against a real machine. What is tested here is the
 * bounded writer and the ABI's argument handling: the code where a mistake is a
 * heap overflow in a process that holds device keys, rather than a missing field
 * in a support bundle.
 *
 * Guard bytes surround every output buffer. A write one byte past the end is the
 * bug this whole design exists to prevent, and a test that only checked the
 * returned length would not notice it.
 */

#include "sardiag.h"
#include "jbuf.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int cond, const char *what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        failures++;
    }
}

#define GUARD 0xA5u
#define PAD 16u

/*
 * run_into writes through jbuf into a padded buffer and verifies the guards.
 *
 * cap is what the writer is told it has; the allocation is larger on both sides,
 * so an off-by-one in either direction is detected rather than silently
 * tolerated by a buffer that happened to be big enough.
 */
static sardiag_status run_into(void (*emit)(jbuf *), uint32_t cap,
                               uint8_t *copy_out, uint32_t *len_out)
{
    static uint8_t arena[8192];
    jbuf b;
    sardiag_status st;
    uint32_t len = 0;
    uint32_t i;

    memset(arena, GUARD, sizeof(arena));
    jbuf_init(&b, arena + PAD, cap);
    emit(&b);
    st = jbuf_finish(&b, &len);

    for (i = 0; i < PAD; i++) {
        check(arena[i] == GUARD, "wrote before the start of the buffer");
    }
    for (i = 0; i < PAD; i++) {
        check(arena[PAD + cap + i] == GUARD, "wrote past the end of the buffer");
    }

    if (copy_out != NULL) {
        uint32_t n = (len < cap) ? len : cap;
        memcpy(copy_out, arena + PAD, n);
        copy_out[n] = '\0';
    }
    if (len_out != NULL) {
        *len_out = len;
    }
    return st;
}

static void emit_hello(jbuf *b)
{
    jbuf_lit(b, "{\"k\":");
    jbuf_str(b, "hello");
    jbuf_lit(b, "}");
}

static void test_fits_exactly(void)
{
    uint8_t got[256];
    uint32_t len = 0;
    sardiag_status st;

    /* Find the required size first, the way a caller does. */
    st = run_into(emit_hello, 0, NULL, &len);
    check(st == SARDIAG_E_TRUNCATED, "a zero-capacity call must report truncation");
    check(len == strlen("{\"k\":\"hello\"}"), "required length is wrong");

    /* Exactly enough must succeed - the boundary an off-by-one lives on. */
    st = run_into(emit_hello, len, got, NULL);
    check(st == SARDIAG_OK, "an exactly-sized buffer must succeed");
    check(strcmp((char *)got, "{\"k\":\"hello\"}") == 0, "output is wrong");

    /* One byte short must fail, and must still report the full requirement. */
    st = run_into(emit_hello, len - 1u, NULL, &len);
    check(st == SARDIAG_E_TRUNCATED, "a one-byte-short buffer must report truncation");
    check(len == strlen("{\"k\":\"hello\"}"), "truncated call must report the full size");
}

static void emit_escapes(jbuf *b)
{
    jbuf_str(b, "a\"b\\c\nd\te\x01");
}

static void test_escaping(void)
{
    uint8_t got[256];
    uint32_t len = 0;

    run_into(emit_escapes, 0, NULL, &len);
    run_into(emit_escapes, len, got, NULL);

    check(strcmp((char *)got, "\"a\\\"b\\\\c\\nd\\te\\u0001\"") == 0,
          "JSON escaping is wrong");
}

static void emit_null_string(jbuf *b)
{
    jbuf_str(b, NULL);
}

static void test_null_string(void)
{
    uint8_t got[16];
    uint32_t len = 0;

    run_into(emit_null_string, 0, NULL, &len);
    run_into(emit_null_string, len, got, NULL);

    /* A missing adapter description must not crash a diagnostic snapshot. */
    check(strcmp((char *)got, "\"\"") == 0, "a NULL string must become an empty JSON string");
}

static void emit_numbers(jbuf *b)
{
    jbuf_lit(b, "[");
    jbuf_u64(b, 0u);
    jbuf_lit(b, ",");
    jbuf_u64(b, 18446744073709551615ull); /* UINT64_MAX */
    jbuf_lit(b, ",");
    jbuf_i64(b, -9223372036854775807LL - 1LL); /* INT64_MIN */
    jbuf_lit(b, ",");
    jbuf_i64(b, -1);
    jbuf_lit(b, "]");
}

static void test_numbers(void)
{
    uint8_t got[256];
    uint32_t len = 0;

    run_into(emit_numbers, 0, NULL, &len);
    run_into(emit_numbers, len, got, NULL);

    /* INT64_MIN is the value that makes the obvious implementation of i64
     * invoke undefined behaviour by negating it in signed space. */
    check(strcmp((char *)got,
                 "[0,18446744073709551615,-9223372036854775808,-1]") == 0,
          "number formatting is wrong");
}

static void emit_utf16(jbuf *b)
{
    /* "Aé" then an emoji as a surrogate pair, then an unpaired high surrogate. */
    static const uint16_t s[] = { 'A', 0x00E9, 0xD83D, 0xDE00, 0xD800, 'Z', 0 };
    jbuf_str_utf16(b, s);
}

static void test_utf16(void)
{
    uint8_t got[256];
    uint32_t len = 0;

    run_into(emit_utf16, 0, NULL, &len);
    run_into(emit_utf16, len, got, NULL);

    check(strcmp((char *)got, "\"A\xC3\xA9\xF0\x9F\x98\x80\xEF\xBF\xBDZ\"") == 0,
          "UTF-16 conversion is wrong; unpaired surrogates must become U+FFFD");
}

static void emit_utf16_null(jbuf *b)
{
    jbuf_str_utf16(b, NULL);
}

static void test_utf16_null(void)
{
    uint8_t got[16];
    uint32_t len = 0;

    run_into(emit_utf16_null, 0, NULL, &len);
    run_into(emit_utf16_null, len, got, NULL);
    check(strcmp((char *)got, "\"\"") == 0, "a NULL wide string must become an empty JSON string");
}

/*
 * test_every_prefix is the test that would catch an off-by-one nothing else does.
 *
 * It writes the same output into every capacity from zero up to one past the
 * required size, checking the guards each time. A bounds error that only fires
 * at one specific capacity - the classic shape - cannot hide from this.
 */
static void test_every_prefix(void)
{
    uint32_t required = 0;
    uint32_t cap;

    run_into(emit_utf16, 0, NULL, &required);

    for (cap = 0; cap <= required + 1u; cap++) {
        uint32_t len = 0;
        sardiag_status st = run_into(emit_utf16, cap, NULL, &len);

        check(len == required, "required length must not depend on the capacity given");
        if (cap >= required) {
            check(st == SARDIAG_OK, "a large enough buffer must succeed");
        } else {
            check(st == SARDIAG_E_TRUNCATED, "a small buffer must report truncation");
        }
    }
}

static void test_abi_arguments(void)
{
    uint8_t buf[64];
    uint32_t len = 0;

    check(sardiag_abi_version() == SARDIAG_ABI_VERSION, "ABI version mismatch");

    /* A NULL length pointer is a caller bug on every entry point. */
    check(sardiag_network_snapshot(buf, sizeof(buf), NULL) == SARDIAG_E_INVALID_ARG,
          "NULL out_len must be rejected");
    check(sardiag_interface_metrics(0, buf, sizeof(buf), NULL) == SARDIAG_E_INVALID_ARG,
          "NULL out_len must be rejected on interface metrics");

    /* A NULL buffer with a non-zero capacity is a caller bug, not a size query.
     * Accepting it would return OK for a snapshot that was never written. */
    check(sardiag_network_snapshot(NULL, 64u, &len) == SARDIAG_E_INVALID_ARG,
          "NULL buffer with non-zero capacity must be rejected");

    /* NULL with zero capacity is the supported size query. It must not be
     * rejected, whatever the platform then reports. */
    check(sardiag_network_snapshot(NULL, 0u, &len) != SARDIAG_E_INVALID_ARG,
          "a zero-capacity size query must be accepted");
}

static void test_status_text(void)
{
    check(strcmp(sardiag_status_text(SARDIAG_OK), "ok") == 0, "status text for OK");
    check(sardiag_status_text((sardiag_status)9999) != NULL,
          "an unknown status must not yield NULL");
    check(strcmp(sardiag_status_text((sardiag_status)9999), "unknown") == 0,
          "an unknown status must say so");
}

int main(void)
{
    test_fits_exactly();
    test_escaping();
    test_null_string();
    test_numbers();
    test_utf16();
    test_utf16_null();
    test_every_prefix();
    test_abi_arguments();
    test_status_text();

    if (failures == 0) {
        printf("sardiag: all tests passed\n");
        return 0;
    }
    printf("sardiag: %d failure(s)\n", failures);
    return 1;
}
