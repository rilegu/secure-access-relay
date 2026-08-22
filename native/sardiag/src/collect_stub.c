/*
 * The non-Windows collector.
 *
 * The library ships on Windows and only Windows: the data it collects comes from
 * the IP Helper and WinHTTP APIs, which have no counterpart worth emulating.
 *
 * This file exists so the portable half - the entry points, the argument
 * checking, and the bounded writer - compiles and runs its tests on every
 * platform CI uses. That half is the one that can corrupt memory, so testing it
 * only where the library ships would be testing it in the fewest places.
 *
 * It returns SARDIAG_E_UNSUPPORTED rather than an empty snapshot. An empty
 * result would be indistinguishable from a machine with no network at all,
 * which is a real condition worth being able to report.
 */

#ifndef _WIN32

#include "collect.h"

sardiag_status sardiag_collect_snapshot(jbuf *b)
{
    (void)b;
    return SARDIAG_E_UNSUPPORTED;
}

sardiag_status sardiag_collect_interface(jbuf *b, uint64_t luid)
{
    (void)b;
    (void)luid;
    return SARDIAG_E_UNSUPPORTED;
}

#endif /* !_WIN32 */

/*
 * ISO C forbids an empty translation unit, and this file is empty on the
 * platform its guard excludes. The typedef gives the compiler something to
 * parse without emitting code or a symbol.
 */
typedef int sardiag_stub_translation_unit_not_empty;
