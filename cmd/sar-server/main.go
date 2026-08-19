// Command sar-server is the secure-access-relay control plane and relay.
//
// The control plane owns identity, enrollment, the resource registry, policy
// evaluation, grant issuance, and audit. The relay pairs already-authorized
// streams between operators and agents.
//
// These are separate package trees with no cross-imports: the relay makes no
// authorization decisions and the control plane carries no payload traffic.
// See docs/decisions/0007-one-binary-two-package-trees.md.
package main

import (
	"fmt"
	"os"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	fmt.Fprintf(os.Stderr, "sar-server %s: not implemented yet\n", version)
	os.Exit(1)
}
