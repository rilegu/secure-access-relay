/*
 * sardiag - network diagnostics for the secure-access-relay agent.
 *
 * This header is the compatibility surface between a C library and a pure-Go
 * agent that loads it at runtime. Everything about it is chosen to make that
 * boundary boring.
 *
 * # The rules this ABI follows
 *
 * 1. **Caller allocates, caller frees.** No function here returns a pointer the
 *    library owns. The agent's memory comes from the Go runtime and the
 *    library's would come from the C runtime it happened to be linked against;
 *    freeing across that line is undefined, and the usual fix - shipping a
 *    matching sardiag_free() - only works if every caller remembers to use it.
 *    Removing the possibility is better than documenting the requirement.
 *
 * 2. **No structs cross the boundary.** Only integers and byte buffers. Struct
 *    layout depends on the compiler, its version, its packing flags, and the
 *    architecture; a mismatch produces silently misread fields rather than a
 *    link error. Output is UTF-8 JSON in a caller-supplied buffer, so the only
 *    agreement needed is "bytes".
 *
 * 3. **Truncation is reported, never performed silently.** When a buffer is too
 *    small the call fails with SARDIAG_E_TRUNCATED and writes the required size
 *    to *out_len, so the caller can allocate and retry. A partially written
 *    buffer is never presented as a complete answer.
 *
 * 4. **The ABI is versioned and the version is queryable before anything else.**
 *    An agent that does not recognise the version refuses to call the rest,
 *    rather than interpreting a layout it does not know.
 *
 * 5. **Nothing here fails the agent.** Every function is diagnostic. A missing,
 *    unloadable, or broken library degrades the support bundle and must never
 *    affect whether authorized access works.
 *
 * # What this library must never do
 *
 *   - It must never read, log, or return key material, tokens, grants, or
 *     payload bytes. It collects network configuration, nothing else.
 *   - It must never modify system state. Every call is a read.
 */

#ifndef SARDIAG_H
#define SARDIAG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SARDIAG_API marks the functions that leave the library.
 *
 * Without it nothing is exported and GetProcAddress finds nothing - a DLL that
 * builds, links, loads, and then cannot be called. That failure is invisible
 * until runtime and looks like a missing file rather than a missing keyword,
 * which is why the build checks the export table rather than trusting that a
 * successful link means a usable library.
 *
 * Defined only when building the library itself; a consumer including this
 * header gets plain declarations.
 */
#if defined(_WIN32)
#  if defined(SARDIAG_BUILD_DLL)
#    define SARDIAG_API __declspec(dllexport)
#  else
#    define SARDIAG_API
#  endif
#elif defined(__GNUC__)
#  define SARDIAG_API __attribute__((visibility("default")))
#else
#  define SARDIAG_API
#endif

/*
 * SARDIAG_ABI_VERSION increments on any change to the signatures, the status
 * codes, or the meaning of a parameter below.
 *
 * It deliberately does *not* increment when a new field appears in the JSON.
 * The agent parses JSON and ignores what it does not recognise, so adding a
 * field is compatible; changing this contract is not.
 */
#define SARDIAG_ABI_VERSION 1u

/* Status codes. Zero is success; everything else is a distinct, stable value. */
typedef enum {
    SARDIAG_OK = 0,

    /* The output buffer was too small. *out_len holds the required size. */
    SARDIAG_E_TRUNCATED = 1,

    /* A required pointer was NULL. */
    SARDIAG_E_INVALID_ARG = 2,

    /* The platform does not implement this collector. */
    SARDIAG_E_UNSUPPORTED = 3,

    /* The operating system refused a query. Partial data is not returned. */
    SARDIAG_E_SYSTEM = 4,

    /* The requested subject does not exist - an unknown interface, say. */
    SARDIAG_E_NOT_FOUND = 5
} sardiag_status;

/*
 * sardiag_abi_version returns SARDIAG_ABI_VERSION as compiled into the library.
 *
 * Call this first and refuse the rest if it is not a version you understand.
 * It takes no arguments and cannot fail, so it is safe to call against a library
 * whose contract you have not yet confirmed - which is exactly the situation a
 * version check exists to resolve.
 */
SARDIAG_API uint32_t sardiag_abi_version(void);

/*
 * sardiag_network_snapshot writes a UTF-8 JSON description of the machine's
 * network configuration: adapters, addresses, routes, DNS servers, and proxy
 * configuration.
 *
 * out      - caller-allocated buffer, may be NULL only if cap is 0
 * cap      - capacity of out in bytes
 * out_len  - receives the number of bytes written on success, or the number of
 *            bytes required on SARDIAG_E_TRUNCATED
 *
 * Passing cap == 0 with a NULL buffer is the supported way to ask how much space
 * is needed: it returns SARDIAG_E_TRUNCATED and sets *out_len.
 *
 * The output is not NUL-terminated. *out_len is the length, and treating the
 * buffer as a C string would read past it.
 */
SARDIAG_API sardiag_status sardiag_network_snapshot(uint8_t *out, uint32_t cap, uint32_t *out_len);

/*
 * sardiag_interface_metrics writes a UTF-8 JSON description of one interface,
 * identified by its Windows LUID.
 *
 * Separate from the snapshot because it is the call worth repeating: a support
 * engineer watching a flapping link wants one interface sampled repeatedly, not
 * the whole machine re-enumerated each time.
 *
 * Returns SARDIAG_E_NOT_FOUND if no interface has that LUID.
 */
SARDIAG_API sardiag_status sardiag_interface_metrics(uint64_t luid, uint8_t *out, uint32_t cap, uint32_t *out_len);

/*
 * sardiag_status_text returns a short, stable, human-readable description of a
 * status code.
 *
 * The returned pointer is to a string literal with static storage duration. It
 * is the one pointer this library hands out, and it is safe precisely because it
 * is never freed and never changes - rule 1 above forbids returning allocated
 * memory, not addresses of constants.
 *
 * An unrecognised code yields "unknown" rather than NULL, so a caller cannot
 * crash while reporting an error it did not expect.
 */
SARDIAG_API const char *sardiag_status_text(sardiag_status status);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SARDIAG_H */
