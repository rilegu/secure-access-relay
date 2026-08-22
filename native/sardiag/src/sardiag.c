/*
 * The ABI entry points.
 *
 * Every function here does the same three things in the same order: validate
 * arguments, hand a bounded writer to a platform collector, report length and
 * status. The collectors never see the caller's pointer arithmetic and the
 * entry points never see the platform's data structures, which keeps the one
 * risky part - writing into somebody else's memory - in a single small file
 * with its own tests.
 */

#include "sardiag.h"
#include "jbuf.h"
#include "collect.h"

SARDIAG_API uint32_t sardiag_abi_version(void)
{
    return SARDIAG_ABI_VERSION;
}

SARDIAG_API const char *sardiag_status_text(sardiag_status status)
{
    switch (status) {
    case SARDIAG_OK:
        return "ok";
    case SARDIAG_E_TRUNCATED:
        return "output buffer too small";
    case SARDIAG_E_INVALID_ARG:
        return "invalid argument";
    case SARDIAG_E_UNSUPPORTED:
        return "not supported on this platform";
    case SARDIAG_E_SYSTEM:
        return "the operating system refused a query";
    case SARDIAG_E_NOT_FOUND:
        return "no such interface";
    default:
        /* Never NULL. A caller reporting an unexpected code must not have to
         * guard against the reporting itself crashing. */
        return "unknown";
    }
}

/*
 * check_args enforces the one calling convention this ABI has.
 *
 * A NULL buffer with a non-zero capacity is a caller bug, not a size query, and
 * is rejected rather than treated as "write nothing" - a caller that made that
 * mistake would otherwise receive SARDIAG_OK for a snapshot it never got.
 */
static sardiag_status check_args(const uint8_t *out, uint32_t cap, const uint32_t *out_len)
{
    if (out_len == NULL) {
        return SARDIAG_E_INVALID_ARG;
    }
    if (out == NULL && cap != 0u) {
        return SARDIAG_E_INVALID_ARG;
    }
    return SARDIAG_OK;
}

SARDIAG_API sardiag_status sardiag_network_snapshot(uint8_t *out, uint32_t cap, uint32_t *out_len)
{
    jbuf b;
    sardiag_status st = check_args(out, cap, out_len);
    if (st != SARDIAG_OK) {
        return st;
    }

    jbuf_init(&b, out, cap);
    st = sardiag_collect_snapshot(&b);
    if (st != SARDIAG_OK) {
        /* A collector failure is reported as itself. The partially written
         * buffer is not described as a result, because a truncated snapshot
         * presented as complete is worse than no snapshot. */
        *out_len = 0u;
        return st;
    }
    return jbuf_finish(&b, out_len);
}

SARDIAG_API sardiag_status sardiag_interface_metrics(uint64_t luid, uint8_t *out, uint32_t cap, uint32_t *out_len)
{
    jbuf b;
    sardiag_status st = check_args(out, cap, out_len);
    if (st != SARDIAG_OK) {
        return st;
    }

    jbuf_init(&b, out, cap);
    st = sardiag_collect_interface(&b, luid);
    if (st != SARDIAG_OK) {
        *out_len = 0u;
        return st;
    }
    return jbuf_finish(&b, out_len);
}
