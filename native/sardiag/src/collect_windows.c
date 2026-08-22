/*
 * Windows network collection.
 *
 * Only reads. Nothing here changes system state, and nothing here touches
 * anything but network configuration - no processes, no files, no registry
 * beyond what the IP Helper and WinHTTP APIs read for themselves.
 *
 * The APIs used return their own allocations, which are freed here before
 * returning. None of them reaches the ABI boundary: the caller's buffer is
 * filled from them and they are released, so the "caller allocates, caller
 * frees" rule holds without the caller ever knowing these existed.
 */

#ifdef _WIN32

#include "collect.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winhttp.h>

#include <stdlib.h>
#include <string.h>

/*
 * initial_adapter_buffer is where the adapter enumeration starts.
 *
 * GetAdaptersAddresses reports the size it needs when given too little, so this
 * is a first guess rather than a limit. 32 KiB covers an ordinary machine in one
 * call; the retry loop below covers the rest.
 */
#define INITIAL_ADAPTER_BUFFER (32u * 1024u)

/* max_adapter_retries bounds the grow-and-retry loop.
 *
 * The required size can legitimately change between calls when an adapter
 * appears, so the loop must retry - but it must not retry forever against a
 * machine whose configuration is changing continuously, which would turn a
 * diagnostic call into a hang. */
#define MAX_ADAPTER_RETRIES 4

/*
 * addr_to_string renders a socket address as text. Returns 0 on failure.
 *
 * getnameinfo with NI_NUMERICHOST rather than inet_ntop, so both address
 * families take one path and link-local IPv6 keeps its scope id - which is
 * exactly the detail a support engineer needs and the one usually missing.
 * WSAAddressToStringA would do the same job and is deprecated; using it builds
 * under gcc and fails under clang, which is a portability trap not worth
 * inheriting for no benefit.
 */
static int addr_to_string(const SOCKET_ADDRESS *sa, char *out, size_t cap)
{
    if (sa == NULL || sa->lpSockaddr == NULL || cap == 0u) {
        return 0;
    }
    if (getnameinfo(sa->lpSockaddr, (socklen_t)sa->iSockaddrLength,
                    out, (DWORD)cap, NULL, 0, NI_NUMERICHOST) != 0) {
        return 0;
    }
    return 1;
}

/* write_addr_list writes a JSON array of address strings from a linked list. */
#define WRITE_ADDR_LIST(b, head, member)                                        \
    do {                                                                        \
        int first_ = 1;                                                         \
        jbuf_lit((b), "[");                                                     \
        for (; (head) != NULL; (head) = (head)->Next) {                         \
            char text_[128];                                                    \
            if (!addr_to_string(&(head)->member, text_, sizeof(text_))) {        \
                continue;                                                       \
            }                                                                   \
            if (!first_) {                                                      \
                jbuf_lit((b), ",");                                             \
            }                                                                   \
            first_ = 0;                                                         \
            jbuf_str((b), text_);                                               \
        }                                                                       \
        jbuf_lit((b), "]");                                                     \
    } while (0)

static void write_mac(jbuf *b, const BYTE *addr, ULONG len)
{
    static const char digits[] = "0123456789abcdef";
    ULONG i;

    jbuf_lit(b, "\"");
    for (i = 0; i < len && i < 32u; i++) {
        if (i > 0u) {
            jbuf_lit(b, ":");
        }
        jbuf_write(b, &digits[(addr[i] >> 4) & 0xFu], 1);
        jbuf_write(b, &digits[addr[i] & 0xFu], 1);
    }
    jbuf_lit(b, "\"");
}

static const char *oper_status_text(IF_OPER_STATUS s)
{
    switch (s) {
    case IfOperStatusUp:
        return "up";
    case IfOperStatusDown:
        return "down";
    case IfOperStatusTesting:
        return "testing";
    case IfOperStatusDormant:
        return "dormant";
    case IfOperStatusNotPresent:
        return "not_present";
    case IfOperStatusLowerLayerDown:
        return "lower_layer_down";
    default:
        return "unknown";
    }
}

/*
 * adapters fetches the adapter list, growing the buffer as the API asks.
 *
 * The caller frees with free(). Returns NULL on failure.
 */
static IP_ADAPTER_ADDRESSES *fetch_adapters(void)
{
    ULONG size = INITIAL_ADAPTER_BUFFER;
    IP_ADAPTER_ADDRESSES *buf = NULL;
    int attempt;

    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX;

    for (attempt = 0; attempt < MAX_ADAPTER_RETRIES; attempt++) {
        ULONG rc;

        free(buf);
        buf = (IP_ADAPTER_ADDRESSES *)malloc(size);
        if (buf == NULL) {
            return NULL;
        }

        rc = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, buf, &size);
        if (rc == NO_ERROR) {
            return buf;
        }
        if (rc != ERROR_BUFFER_OVERFLOW) {
            free(buf);
            return NULL;
        }
        /* size now holds what the API wants; loop and try again. */
    }

    free(buf);
    return NULL;
}

/* write_adapter writes one adapter as a JSON object. */
static void write_adapter(jbuf *b, const IP_ADAPTER_ADDRESSES *a)
{
    IP_ADAPTER_UNICAST_ADDRESS *unicast = a->FirstUnicastAddress;
    IP_ADAPTER_DNS_SERVER_ADDRESS *dns = a->FirstDnsServerAddress;
    IP_ADAPTER_GATEWAY_ADDRESS *gateway = a->FirstGatewayAddress;

    jbuf_lit(b, "{\"luid\":");
    jbuf_u64(b, (uint64_t)a->Luid.Value);
    jbuf_lit(b, ",\"index\":");
    jbuf_u64(b, (uint64_t)a->IfIndex);
    jbuf_lit(b, ",\"name\":");
    jbuf_str(b, a->AdapterName);
    jbuf_lit(b, ",\"friendly_name\":");
    jbuf_str_utf16(b, (const uint16_t *)a->FriendlyName);
    jbuf_lit(b, ",\"description\":");
    jbuf_str_utf16(b, (const uint16_t *)a->Description);
    jbuf_lit(b, ",\"status\":");
    jbuf_str(b, oper_status_text(a->OperStatus));
    jbuf_lit(b, ",\"mtu\":");
    jbuf_u64(b, (uint64_t)a->Mtu);
    jbuf_lit(b, ",\"type\":");
    jbuf_u64(b, (uint64_t)a->IfType);
    jbuf_lit(b, ",\"mac\":");
    write_mac(b, a->PhysicalAddress, a->PhysicalAddressLength);

    jbuf_lit(b, ",\"addresses\":");
    WRITE_ADDR_LIST(b, unicast, Address);
    jbuf_lit(b, ",\"dns_servers\":");
    WRITE_ADDR_LIST(b, dns, Address);
    jbuf_lit(b, ",\"gateways\":");
    WRITE_ADDR_LIST(b, gateway, Address);

    jbuf_lit(b, "}");
}

/*
 * write_routes writes the IPv4 and IPv6 route tables.
 *
 * A failure here is written as an empty array rather than failing the whole
 * snapshot. Routes are one section of a diagnostic; losing them should not cost
 * the adapter list, which is usually what the question was about anyway.
 */
static void write_routes(jbuf *b)
{
    MIB_IPFORWARD_TABLE2 *table = NULL;
    ULONG i;
    int first = 1;

    jbuf_lit(b, "[");
    if (GetIpForwardTable2(AF_UNSPEC, &table) != NO_ERROR || table == NULL) {
        jbuf_lit(b, "]");
        return;
    }

    for (i = 0; i < table->NumEntries; i++) {
        const MIB_IPFORWARD_ROW2 *r = &table->Table[i];
        char dest[128];
        char next[128];
        SOCKET_ADDRESS da;
        SOCKET_ADDRESS na;

        da.lpSockaddr = (LPSOCKADDR)&r->DestinationPrefix.Prefix;
        da.iSockaddrLength = sizeof(SOCKADDR_INET);
        na.lpSockaddr = (LPSOCKADDR)&r->NextHop;
        na.iSockaddrLength = sizeof(SOCKADDR_INET);

        if (!addr_to_string(&da, dest, sizeof(dest))) {
            continue;
        }
        if (!addr_to_string(&na, next, sizeof(next))) {
            next[0] = '\0';
        }

        if (!first) {
            jbuf_lit(b, ",");
        }
        first = 0;

        jbuf_lit(b, "{\"destination\":");
        jbuf_str(b, dest);
        jbuf_lit(b, ",\"prefix_length\":");
        jbuf_u64(b, (uint64_t)r->DestinationPrefix.PrefixLength);
        jbuf_lit(b, ",\"next_hop\":");
        jbuf_str(b, next);
        jbuf_lit(b, ",\"interface_index\":");
        jbuf_u64(b, (uint64_t)r->InterfaceIndex);
        jbuf_lit(b, ",\"metric\":");
        jbuf_u64(b, (uint64_t)r->Metric);
        jbuf_lit(b, ",\"loopback\":");
        jbuf_bool(b, r->Loopback ? 1 : 0);
        jbuf_lit(b, "}");
    }

    FreeMibTable(table);
    jbuf_lit(b, "]");
}

/*
 * write_proxy reports the machine-wide WinHTTP proxy configuration.
 *
 * The machine configuration, not the interactive user's: the agent runs as a
 * service, so the per-user Internet Settings a support engineer sees in their
 * own session are not the ones the agent will use. Reporting the user's would
 * be actively misleading during exactly the outage this is meant to explain.
 */
static void write_proxy(jbuf *b)
{
    WINHTTP_PROXY_INFO info;

    memset(&info, 0, sizeof(info));

    jbuf_lit(b, "{");
    if (!WinHttpGetDefaultProxyConfiguration(&info)) {
        jbuf_lit(b, "\"available\":false}");
        return;
    }

    jbuf_lit(b, "\"available\":true,\"access_type\":");
    jbuf_u64(b, (uint64_t)info.dwAccessType);
    jbuf_lit(b, ",\"proxy\":");
    jbuf_str_utf16(b, (const uint16_t *)info.lpszProxy);
    jbuf_lit(b, ",\"bypass\":");
    jbuf_str_utf16(b, (const uint16_t *)info.lpszProxyBypass);
    jbuf_lit(b, "}");

    /* These are WinHTTP's allocations, released here. They never reach the ABI
     * boundary; their contents were copied into the caller's buffer above. */
    if (info.lpszProxy != NULL) {
        GlobalFree(info.lpszProxy);
    }
    if (info.lpszProxyBypass != NULL) {
        GlobalFree(info.lpszProxyBypass);
    }
}

sardiag_status sardiag_collect_snapshot(jbuf *b)
{
    IP_ADAPTER_ADDRESSES *list = fetch_adapters();
    IP_ADAPTER_ADDRESSES *a;
    int first = 1;

    if (list == NULL) {
        return SARDIAG_E_SYSTEM;
    }

    jbuf_lit(b, "{\"abi_version\":");
    jbuf_u64(b, (uint64_t)SARDIAG_ABI_VERSION);
    jbuf_lit(b, ",\"platform\":\"windows\",\"adapters\":[");

    for (a = list; a != NULL; a = a->Next) {
        if (!first) {
            jbuf_lit(b, ",");
        }
        first = 0;
        write_adapter(b, a);
    }

    jbuf_lit(b, "],\"routes\":");
    write_routes(b);
    jbuf_lit(b, ",\"proxy\":");
    write_proxy(b);
    jbuf_lit(b, "}");

    free(list);
    return SARDIAG_OK;
}

sardiag_status sardiag_collect_interface(jbuf *b, uint64_t luid)
{
    IP_ADAPTER_ADDRESSES *list = fetch_adapters();
    IP_ADAPTER_ADDRESSES *a;
    sardiag_status st = SARDIAG_E_NOT_FOUND;

    if (list == NULL) {
        return SARDIAG_E_SYSTEM;
    }

    for (a = list; a != NULL; a = a->Next) {
        if ((uint64_t)a->Luid.Value == luid) {
            write_adapter(b, a);
            st = SARDIAG_OK;
            break;
        }
    }

    free(list);
    return st;
}

#endif /* _WIN32 */

/*
 * ISO C forbids an empty translation unit, and this file is empty on the
 * platform its guard excludes. The typedef gives the compiler something to
 * parse without emitting code or a symbol.
 */
typedef int sardiag_windows_translation_unit_not_empty;
