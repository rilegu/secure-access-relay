#include "jbuf.h"

#include <string.h>

void jbuf_init(jbuf *b, uint8_t *out, uint32_t cap)
{
    b->out = out;
    b->cap = (out == NULL) ? 0u : cap;
    b->needed = 0u;
}

/*
 * jbuf_put is the only place a byte is written, so it is the only place a bounds
 * check has to be right.
 *
 * The index is the running total, which is always the position this byte would
 * occupy. Comparing it against the capacity is the whole check; there is no
 * cursor to advance and no remaining-count to keep in step.
 */
static void jbuf_put(jbuf *b, uint8_t c)
{
    if (b->needed < (uint64_t)b->cap) {
        b->out[b->needed] = c;
    }
    b->needed++;
}

void jbuf_write(jbuf *b, const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        jbuf_put(b, (uint8_t)s[i]);
    }
}

void jbuf_lit(jbuf *b, const char *s)
{
    if (s == NULL) {
        return;
    }
    jbuf_write(b, s, strlen(s));
}

/* hexdigit returns the lowercase hex character for the low nibble of v. */
static char hexdigit(unsigned v)
{
    static const char digits[] = "0123456789abcdef";
    return digits[v & 0xFu];
}

/*
 * escape_byte writes one byte of a JSON string, escaping what RFC 8259 requires.
 *
 * Control characters below 0x20 are escaped numerically rather than dropped: a
 * stray byte in an adapter description should be visible in the output, not
 * silently removed, because an unexplained character is a clue and an absent one
 * is nothing.
 *
 * Bytes at or above 0x80 pass through. Every string reaching here is either an
 * ASCII literal or the output of the UTF-16 conversion below, so the result is
 * valid UTF-8 by construction rather than by hope.
 */
static void escape_byte(jbuf *b, uint8_t c)
{
    switch (c) {
    case '"':
        jbuf_lit(b, "\\\"");
        return;
    case '\\':
        jbuf_lit(b, "\\\\");
        return;
    case '\n':
        jbuf_lit(b, "\\n");
        return;
    case '\r':
        jbuf_lit(b, "\\r");
        return;
    case '\t':
        jbuf_lit(b, "\\t");
        return;
    case '\b':
        jbuf_lit(b, "\\b");
        return;
    case '\f':
        jbuf_lit(b, "\\f");
        return;
    default:
        break;
    }

    if (c < 0x20u) {
        jbuf_lit(b, "\\u00");
        jbuf_put(b, (uint8_t)hexdigit(c >> 4));
        jbuf_put(b, (uint8_t)hexdigit(c));
        return;
    }
    jbuf_put(b, c);
}

void jbuf_strn(jbuf *b, const char *s, size_t n)
{
    size_t i;

    jbuf_put(b, (uint8_t)'"');
    if (s != NULL) {
        for (i = 0; i < n; i++) {
            escape_byte(b, (uint8_t)s[i]);
        }
    }
    jbuf_put(b, (uint8_t)'"');
}

void jbuf_str(jbuf *b, const char *s)
{
    jbuf_strn(b, s, (s == NULL) ? 0u : strlen(s));
}

void jbuf_u64(jbuf *b, uint64_t v)
{
    /* 20 digits is the widest uint64_t, and the buffer is local, so this cannot
     * be the overflow the rest of the file is written to avoid. */
    char tmp[20];
    int n = 0;

    if (v == 0u) {
        jbuf_put(b, (uint8_t)'0');
        return;
    }
    while (v > 0u && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (n > 0) {
        jbuf_put(b, (uint8_t)tmp[--n]);
    }
}

void jbuf_i64(jbuf *b, int64_t v)
{
    if (v < 0) {
        jbuf_put(b, (uint8_t)'-');
        /* Negated in unsigned space so INT64_MIN does not overflow on negation,
         * which is undefined behaviour and the classic bug in this function. */
        jbuf_u64(b, (uint64_t)0 - (uint64_t)v);
        return;
    }
    jbuf_u64(b, (uint64_t)v);
}

void jbuf_bool(jbuf *b, int v)
{
    jbuf_lit(b, v ? "true" : "false");
}

sardiag_status jbuf_finish(const jbuf *b, uint32_t *out_len)
{
    if (out_len == NULL) {
        return SARDIAG_E_INVALID_ARG;
    }

    /* A snapshot larger than a 32-bit length is not representable in this ABI.
     * Reported as truncation with the capacity clamped rather than as a wrapped
     * small number, because the caller's retry must not appear to succeed. */
    if (b->needed > 0xFFFFFFFFull) {
        *out_len = 0xFFFFFFFFu;
        return SARDIAG_E_TRUNCATED;
    }

    *out_len = (uint32_t)b->needed;
    return (b->needed <= (uint64_t)b->cap) ? SARDIAG_OK : SARDIAG_E_TRUNCATED;
}

/* put_utf8 encodes one Unicode scalar value as UTF-8 and escapes it. */
static void put_utf8(jbuf *b, uint32_t cp)
{
    if (cp < 0x80u) {
        escape_byte(b, (uint8_t)cp);
    } else if (cp < 0x800u) {
        jbuf_put(b, (uint8_t)(0xC0u | (cp >> 6)));
        jbuf_put(b, (uint8_t)(0x80u | (cp & 0x3Fu)));
    } else if (cp < 0x10000u) {
        jbuf_put(b, (uint8_t)(0xE0u | (cp >> 12)));
        jbuf_put(b, (uint8_t)(0x80u | ((cp >> 6) & 0x3Fu)));
        jbuf_put(b, (uint8_t)(0x80u | (cp & 0x3Fu)));
    } else {
        jbuf_put(b, (uint8_t)(0xF0u | (cp >> 18)));
        jbuf_put(b, (uint8_t)(0x80u | ((cp >> 12) & 0x3Fu)));
        jbuf_put(b, (uint8_t)(0x80u | ((cp >> 6) & 0x3Fu)));
        jbuf_put(b, (uint8_t)(0x80u | (cp & 0x3Fu)));
    }
}

void jbuf_str_utf16(jbuf *b, const uint16_t *s)
{
    size_t i = 0;

    jbuf_put(b, (uint8_t)'"');
    if (s == NULL) {
        jbuf_put(b, (uint8_t)'"');
        return;
    }

    while (s[i] != 0u) {
        uint32_t cp = s[i];

        if (cp >= 0xD800u && cp <= 0xDBFFu) {
            uint32_t low = s[i + 1];
            if (low >= 0xDC00u && low <= 0xDFFFu) {
                cp = 0x10000u + ((cp - 0xD800u) << 10) + (low - 0xDC00u);
                i += 2;
            } else {
                /* An unpaired high surrogate. Replaced rather than encoded: a
                 * lone surrogate is not a valid scalar value, and emitting one
                 * would produce UTF-8 that a strict decoder rejects - turning a
                 * cosmetic problem in an adapter name into an unparseable
                 * snapshot. */
                cp = 0xFFFDu;
                i += 1;
            }
        } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
            cp = 0xFFFDu; /* unpaired low surrogate */
            i += 1;
        } else {
            i += 1;
        }

        put_utf8(b, cp);
    }

    jbuf_put(b, (uint8_t)'"');
}
