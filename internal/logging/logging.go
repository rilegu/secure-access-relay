package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New returns the process logger.
//
// Output is line-delimited JSON on stderr. JSON rather than a human format
// because these logs are meant to be shipped and queried, and every event that
// matters carries structured fields (reason codes, stream IDs, byte counts) that
// a prose log line would flatten into something ungreppable.
//
// Invariant 7 governs what may be logged: never secrets, bearer tokens, private
// keys, grant signatures, or payload bytes. There is no redaction layer yet
// because nothing sensitive is passed to a logger at this stage; when credentials
// arrive, the redactor lands with them rather than after.
func New(level string) *slog.Logger {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLevel(level),
	})
	return slog.New(h)
}

// parseLevel maps a level name onto a slog level, defaulting to info.
//
// An unrecognised name deliberately falls back to info rather than failing
// startup: a typo in a log level should not stop a service from running, and the
// wrong verbosity is a much smaller problem than an endpoint agent that refuses
// to start.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
