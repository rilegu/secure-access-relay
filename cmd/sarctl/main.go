// Command sarctl is the secure-access-relay operator CLI.
//
// It authenticates the operator, requests a short-lived signed grant, opens a
// local listener, and carries that traffic through the relay to an approved
// resource on an enrolled device.
//
// The operator names a resource ID. They never supply a target address.
package main

import (
	"fmt"
	"os"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	fmt.Fprintf(os.Stderr, "sarctl %s: not implemented yet\n", version)
	os.Exit(1)
}
