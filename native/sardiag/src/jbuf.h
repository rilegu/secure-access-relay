/*
 * jbuf - a bounded JSON writer that cannot overrun its buffer.
 *
 * # Why this exists rather than snprintf into a moving cursor
 *
 * The usual shape of this code keeps a pointer and a remaining count, advances
 * both after every write, and gets it wrong once. That single mistake is a heap
 * overflow in a library loaded into a process that holds device keys.
 *
 * So the buffer is never advanced. jbuf tracks how many bytes the output *would*
 * need, and writes a byte only when its index is inside the capacity. Every
 * write is therefore bounds-checked by construction, the arithmetic that could
 * be wrong does not exist, and the required size falls out of the same counter -
 * which is exactly what the ABI has to report on truncation.
 *
 * The counter is 64-bit while the capacity is 32-bit, so a snapshot larger than
 * 4 GiB cannot wrap the counter into a small number and turn a truncation into
 * an apparent success.
 */

#ifndef SARDIAG_JBUF_H
#define SARDIAG_JBUF_H

#include <stddef.h>
#include <stdint.h>

#include "sardiag.h"

typedef struct {
    uint8_t *out;   /* may be NULL when cap is 0 */
    uint32_t cap;
    uint64_t needed; /* total bytes required, whether or not they fit */
} jbuf;

void jbuf_init(jbuf *b, uint8_t *out, uint32_t cap);

/* Append raw bytes with no interpretation. */
void jbuf_write(jbuf *b, const char *s, size_t n);

/* Append a NUL-terminated literal with no escaping. For punctuation and keys
 * that are known-safe at the call site. */
void jbuf_lit(jbuf *b, const char *s);

/* Append a JSON string, including the surrounding quotes, escaping as required.
 * A NULL pointer is written as an empty string rather than crashing: a missing
 * adapter description is not a reason to fail a diagnostic snapshot. */
void jbuf_str(jbuf *b, const char *s);

/* Append a JSON string from a length-delimited byte range. */
void jbuf_strn(jbuf *b, const char *s, size_t n);

void jbuf_u64(jbuf *b, uint64_t v);
void jbuf_i64(jbuf *b, int64_t v);
void jbuf_bool(jbuf *b, int v);

/*
 * jbuf_finish reports the outcome and writes the length.
 *
 * SARDIAG_OK when everything fit, SARDIAG_E_TRUNCATED otherwise - and in both
 * cases *out_len receives the number of bytes the complete output needs, so a
 * caller can allocate exactly that and retry.
 */
sardiag_status jbuf_finish(const jbuf *b, uint32_t *out_len);

/*
 * utf16_to_utf8 converts a NUL-terminated UTF-16 string into the buffer as an
 * escaped JSON string.
 *
 * Written here rather than left to the platform because the output must be
 * valid UTF-8 for the agent to parse: passing UTF-16 bytes through, or trusting
 * a locale-dependent conversion, produces JSON that fails to decode on a machine
 * with a different code page. Unpaired surrogates become U+FFFD rather than
 * invalid sequences.
 *
 * Declared unconditionally so the tests can exercise it on any platform.
 */
void jbuf_str_utf16(jbuf *b, const uint16_t *s);

#endif /* SARDIAG_JBUF_H */
