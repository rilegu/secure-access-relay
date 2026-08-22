package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rilegu/secure-access-relay/internal/diagbridge"
)

// cmdDiag prints the network diagnostics snapshot.
//
// # Why this is a command rather than something the agent does on its own
//
// The agent never collects diagnostics unprompted. Reading a machine's network
// configuration is legitimate when somebody is debugging and gratuitous
// otherwise, and a service that gathers system state on a timer is a service
// that has to explain why. Somebody asks; the agent answers.
//
// The output goes to stdout as JSON so it can be redirected into a ticket or
// piped through a filter, and so that adding a field later does not break
// whatever is reading it.
func cmdDiag(args []string) error {
	fs := flag.NewFlagSet("diag", flag.ExitOnError)
	var (
		libDir        = fs.String("lib-dir", "", "directory holding sardiag (default: alongside the executable)")
		allowUnsigned = fs.Bool("allow-unsigned", false,
			"load the library even if its Authenticode signature does not verify; for development only")
		iface = fs.Uint64("interface", 0, "report one interface by LUID instead of the whole machine")
	)
	_ = fs.Parse(args)

	dir := *libDir
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate executable: %w", err)
		}
		// Alongside the binary, which on an installed system is the
		// ACL-protected Program Files directory. Never the working directory.
		dir = filepath.Dir(exe)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}

	lib, err := diagbridge.Open(diagbridge.Config{Dir: abs, AllowUnsigned: *allowUnsigned})
	if err != nil {
		// Each of these is a different situation for whoever is reading, so they
		// are reported differently rather than as one "diagnostics failed".
		switch {
		case errors.Is(err, diagbridge.ErrUnsupportedPlatform):
			return fmt.Errorf("network diagnostics are available on Windows only")
		case errors.Is(err, diagbridge.ErrUntrusted):
			return fmt.Errorf("%w\n\nthe file is present and was refused, which is worth investigating "+
				"before working around it with -allow-unsigned", err)
		case errors.Is(err, diagbridge.ErrABIMismatch):
			return fmt.Errorf("%w\n\nthe library and this agent are from different releases", err)
		default:
			return fmt.Errorf("%w\n\nlooked in %s; the agent runs normally without it", err, abs)
		}
	}
	defer func() { _ = lib.Close() }()

	if *iface != 0 {
		raw, err := lib.InterfaceMetrics(*iface)
		if err != nil {
			return err
		}
		return printJSON(raw)
	}

	snap, err := lib.Snapshot()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return printJSON(encoded)
}

// printJSON writes indented JSON to stdout.
func printJSON(raw []byte) error {
	var pretty map[string]any
	if err := json.Unmarshal(raw, &pretty); err != nil {
		// Printed as-is rather than swallowed. If the library produced something
		// this build cannot parse, seeing it is more use than being told it could
		// not be parsed.
		_, werr := os.Stdout.Write(raw)
		return werr
	}
	out, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}
