// Command sar-agent is the secure-access-relay endpoint agent.
//
// It runs as a Windows Service on the protected endpoint, holds a persistent
// outbound mTLS connection to sar-server, verifies signed grants locally, and
// dials only loopback targets listed in its own resource allowlist.
//
// The agent never listens on a network interface.
package main

import (
	"fmt"
	"os"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	fmt.Fprintf(os.Stderr, "sar-agent %s: not implemented yet\n", version)
	os.Exit(1)
}
