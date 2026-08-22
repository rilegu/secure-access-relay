/*
 * The platform boundary.
 *
 * Everything above this line is portable and tested everywhere; everything
 * below it is Windows. Splitting here rather than sprinkling #ifdef through the
 * entry points means the buffer handling - the part that can corrupt memory -
 * is compiled and tested on every platform the CI runs, not only on the one
 * where the library ships.
 */

#ifndef SARDIAG_COLLECT_H
#define SARDIAG_COLLECT_H

#include "sardiag.h"
#include "jbuf.h"

/* Writes the whole-machine snapshot as a JSON object. */
sardiag_status sardiag_collect_snapshot(jbuf *b);

/* Writes one interface as a JSON object, or SARDIAG_E_NOT_FOUND. */
sardiag_status sardiag_collect_interface(jbuf *b, uint64_t luid);

#endif /* SARDIAG_COLLECT_H */
