//go:build !windows

package logging

import "errors"

// Platforms without a Windows Event Log get no event sink. The equivalent
// arrangement elsewhere is the system journal, which reads the process's stderr
// — and that already receives the structured JSON log.

var errNoEventLog = errors.New("logging: no event log on this platform")

func registerSource(string) error   { return errNoEventLog }
func deregisterSource(string) error { return errNoEventLog }

func newEventSink(string) (eventSink, error) { return nil, errNoEventLog }
