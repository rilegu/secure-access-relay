package logging

import (
	"context"
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

// eventSink receives operational events for a platform's native log.
//
// Only a handful of severities, and only a message: this is deliberately not a
// second structured logging system. The JSON log is the machine-readable record;
// the native log exists so an administrator looking in the usual place finds
// something rather than nothing.
type eventSink interface {
	Info(msg string) error
	Warn(msg string) error
	Error(msg string) error
	Close() error
}

// RegisterEventSource prepares the platform's native log to receive events from
// this program. It needs Administrator rights and is called at install time.
func RegisterEventSource(source string) error { return registerSource(source) }

// DeregisterEventSource removes that preparation, so an uninstall leaves nothing
// behind.
func DeregisterEventSource(source string) error { return deregisterSource(source) }

// NewWithEventLog returns a logger that writes structured JSON to stderr and
// also mirrors notable events to the platform's native log.
//
// If the native log is unavailable — wrong platform, source not registered,
// insufficient rights — the JSON logger is returned unchanged along with the
// reason. That is deliberate: an agent that cannot write to the Event Log must
// keep serving, because the alternative is an endpoint that goes offline over a
// logging problem.
func NewWithEventLog(level, source string) (*slog.Logger, func(), error) {
	base := New(level)

	sink, err := newEventSink(source)
	if err != nil {
		return base, func() {}, err
	}

	h := &teeHandler{
		primary: base.Handler(),
		sink:    sink,
		// Only warnings and above reach the native log. Windows event logs are a
		// shared, size-limited resource; filling one with routine informational
		// events makes every other program's events harder to find.
		minLevel: slog.LevelWarn,
	}
	return slog.New(h), func() { _ = sink.Close() }, nil
}

// teeHandler writes to a primary handler and mirrors records to an event sink.
type teeHandler struct {
	primary  slog.Handler
	sink     eventSink
	minLevel slog.Level
	attrs    []slog.Attr
	group    string
}

func (h *teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.primary.Enabled(ctx, l)
}

func (h *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	// The JSON record is the authoritative one and is written first, so a
	// failure mirroring to the native log cannot lose it.
	err := h.primary.Handle(ctx, r)

	if r.Level >= h.minLevel && h.sink != nil {
		msg := renderEvent(r, h.attrs)
		switch {
		case r.Level >= slog.LevelError:
			_ = h.sink.Error(msg)
		default:
			_ = h.sink.Warn(msg)
		}
	}
	return err
}

func (h *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &teeHandler{
		primary:  h.primary.WithAttrs(attrs),
		sink:     h.sink,
		minLevel: h.minLevel,
		attrs:    append(append([]slog.Attr{}, h.attrs...), attrs...),
		group:    h.group,
	}
}

func (h *teeHandler) WithGroup(name string) slog.Handler {
	return &teeHandler{
		primary:  h.primary.WithGroup(name),
		sink:     h.sink,
		minLevel: h.minLevel,
		attrs:    h.attrs,
		group:    name,
	}
}

// renderEvent flattens a record into one human-readable line.
//
// The native log has no structure to preserve, so attributes are appended as
// key=value. Invariant 7 still applies: nothing reaches a logger that must not
// be logged, so there is nothing to redact here.
func renderEvent(r slog.Record, extra []slog.Attr) string {
	var b strings.Builder
	b.WriteString(r.Message)

	writeAttr := func(a slog.Attr) {
		b.WriteString(" ")
		b.WriteString(a.Key)
		b.WriteString("=")
		b.WriteString(a.Value.String())
	}
	for _, a := range extra {
		writeAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(a)
		return true
	})
	return b.String()
}
