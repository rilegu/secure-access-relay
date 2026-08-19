/*
 * sardiag - Windows network diagnostics for secure-access-relay.
 *
 * ABI contract. See docs/decisions/0005-native-c-dynamically-loaded.md.
 *
 *   - This is a C interface. No C++ types, classes, exceptions, or STL objects
 *     cross this boundary under any circumstances.
 *   - The caller allocates and owns every output buffer. This library never
 *     returns a pointer it owns and never requires the caller to free anything.
 *   - Every function returns a SARDIAG_* status code. Zero is success.
 *   - On SARDIAG_ERR_BUFFER_TOO_SMALL, *out_len receives the required size and
 *     the buffer contents are unspecified.
 *   - Output payloads are UTF-8 JSON and are NOT null-terminated; use *out_len.
 *   - This library reads system state only. It performs no privileged action,
 *     no network I/O, and no code execution on behalf of a caller.
 *
 * Loaded dynamically by the Go agent from an absolute path in the ACL-protected
 * install directory, with the Authenticode signature verified before load.
 */

#ifndef SARDIAG_H
#define SARDIAG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Incremented on any breaking ABI change. Callers must check. */
#define SARDIAG_ABI_VERSION 1

/* Status codes. Stable; values never change meaning. */
#define SARDIAG_OK                     0
#define SARDIAG_ERR_INVALID_ARG        1
#define SARDIAG_ERR_BUFFER_TOO_SMALL   2
#define SARDIAG_ERR_OS_CALL_FAILED     3
#define SARDIAG_ERR_UNSUPPORTED        4
#define SARDIAG_ERR_INTERNAL           5

/* Returns SARDIAG_ABI_VERSION of the loaded library. */
uint32_t sardiag_abi_version(void);

/*
 * Collects a network snapshot: adapter status, LUID/GUID, MTU, operational
 * state, route table summary, default routes, DNS servers and suffixes, and
 * active proxy configuration. Output is UTF-8 JSON.
 */
int32_t sardiag_network_snapshot(uint8_t *out, uint32_t cap, uint32_t *out_len);

/* Per-interface counters and state for the given interface LUID. UTF-8 JSON. */
int32_t sardiag_interface_metrics(uint64_t luid, uint8_t *out, uint32_t cap, uint32_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SARDIAG_H */
