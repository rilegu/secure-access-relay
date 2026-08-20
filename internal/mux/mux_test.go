package mux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// pair builds two connected sessions over an in-memory pipe.
//
// net.Pipe is synchronous and unbuffered, which is useful here: it removes the
// kernel socket buffer, so anything that appears to work only because a few
// hundred kilobytes happened to fit in a buffer will deadlock instead. Flow
// control has to be real for these tests to pass.
func pair(t *testing.T, cfg func(*Config)) (client, server *Session) {
	t.Helper()

	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })

	base := Config{
		MaxFramePayload: 4096,
		InitialWindow:   16384,
		MaxStreams:      4,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if cfg != nil {
		cfg(&base)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	type result struct {
		s   *Session
		err error
	}
	srvCh := make(chan result, 1)
	go func() {
		sc := base
		sc.Role = proto.RoleAgent
		h, err := Accept(ctx, transport.NewConn(s), sc)
		if err != nil {
			srvCh <- result{nil, err}
			return
		}
		sess, err := h.Admit("ses_test")
		srvCh <- result{sess, err}
	}()

	cc := base
	cc.Role = proto.RoleOperator
	client, err := Dial(ctx, transport.NewConn(c), cc, proto.Auth{DeviceID: "dev_test", UserID: "usr_test"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	r := <-srvCh
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}

	t.Cleanup(func() {
		_ = client.Close(proto.ReasonShutdown)
		_ = r.s.Close(proto.ReasonShutdown)
	})
	return client, r.s
}

func TestHandshakeCarriesIdentityAndLimits(t *testing.T) {
	client, server := pair(t, nil)

	if client.ID != "ses_test" {
		t.Errorf("client session id = %q, want %q", client.ID, "ses_test")
	}
	// The responder sees what the initiator claimed. Nothing is proved by it,
	// but it must arrive intact.
	if server.Peer.DeviceID != "dev_test" || server.Peer.UserID != "usr_test" {
		t.Errorf("server saw peer %+v, want device dev_test user usr_test", server.Peer)
	}
	if client.maxFrame != 4096 || client.window != 16384 {
		t.Errorf("client limits = frame %d window %d, want 4096/16384", client.maxFrame, client.window)
	}
}

func TestStreamRoundTrip(t *testing.T) {
	client, server := pair(t, nil)
	ctx := context.Background()

	go func() {
		st, err := server.AcceptStream(ctx)
		if err != nil {
			return
		}
		defer func() { _ = st.Close() }()
		_, _ = io.Copy(st, st) // echo
	}()

	st, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	want := []byte("hello through the multiplexer")
	if _, err := st.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := st.Close(); err != nil { // half-close: we are done sending
		t.Fatalf("close: %v", err)
	}

	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echoed %q, sent %q", got, want)
	}
}

// TestHalfCloseAllowsResponse is the property that makes request/response
// protocols work through a stream.
//
// A client that finishes its request and closes its side must still be able to
// read the reply. If Close tore down both directions, every HTTP request through
// this multiplexer would lose its response.
func TestHalfCloseAllowsResponse(t *testing.T) {
	client, server := pair(t, nil)
	ctx := context.Background()

	go func() {
		st, err := server.AcceptStream(ctx)
		if err != nil {
			return
		}
		// Read to EOF — the peer's half-close — then reply on the still-open
		// direction.
		req, _ := io.ReadAll(st)
		_, _ = st.Write(append([]byte("reply to "), req...))
		_ = st.Close()
	}()

	st, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.Write([]byte("request")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("half-close: %v", err)
	}

	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if string(got) != "reply to request" {
		t.Fatalf("got %q, want %q", got, "reply to request")
	}
}

// TestConcurrentStreamsStayIsolated is the core multiplexing property: several
// streams share one connection and none of them sees another's bytes.
func TestConcurrentStreamsStayIsolated(t *testing.T) {
	client, server := pair(t, func(c *Config) { c.MaxStreams = 8 })
	ctx := context.Background()

	go func() {
		for {
			st, err := server.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func(st *Stream) {
				defer func() { _ = st.Close() }()
				_, _ = io.Copy(st, st)
			}(st)
		}
	}()

	const streams = 8
	var wg sync.WaitGroup
	errs := make(chan error, streams)

	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			st, err := client.Open(ctx)
			if err != nil {
				errs <- err
				return
			}
			// Each stream sends a distinct byte value, so a crossed stream shows
			// up as mixed content rather than merely as a wrong length.
			payload := bytes.Repeat([]byte{byte('A' + n)}, 40*1024)
			go func() {
				_, _ = st.Write(payload)
				_ = st.Close()
			}()
			got, err := io.ReadAll(st)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, payload) {
				errs <- errors.New("stream contents crossed between streams")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent streams: %v", err)
	}
}

// TestFlowControlBoundsBuffering checks that a writer cannot outrun a reader.
//
// The writer sends far more than one window with no reader draining. It must
// block once the window is spent rather than buffering everything, and it must
// resume when the reader starts consuming.
func TestFlowControlBoundsBuffering(t *testing.T) {
	client, server := pair(t, func(c *Config) {
		c.InitialWindow = 8192
		c.MaxFramePayload = 1024
	})
	ctx := context.Background()

	accepted := make(chan *Stream, 1)
	go func() {
		st, err := server.AcceptStream(ctx)
		if err == nil {
			accepted <- st
		}
	}()

	st, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	remote := <-accepted

	const total = 128 * 1024 // sixteen windows

	writeDone := make(chan error, 1)
	go func() {
		_, err := st.Write(bytes.Repeat([]byte{0x5A}, total))
		writeDone <- err
	}()

	// The write must not complete while nothing is reading.
	select {
	case err := <-writeDone:
		t.Fatalf("write of %d bytes completed with a %d-byte window and no reader (err=%v): "+
			"flow control is not limiting the sender", total, 8192, err)
	case <-time.After(200 * time.Millisecond):
	}

	// Draining releases credit and the writer should finish.
	got := make([]byte, 0, total)
	buf := make([]byte, 4096)
	for len(got) < total {
		n, err := remote.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(got), err)
		}
	}

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("write never completed after the reader drained")
	}

	if len(got) != total {
		t.Fatalf("received %d bytes, want %d", len(got), total)
	}
}

// TestLargeTransferIntegrity moves far more than one window and verifies the
// bytes, which is what catches a windowing bug that loses or duplicates a chunk.
func TestLargeTransferIntegrity(t *testing.T) {
	client, server := pair(t, func(c *Config) {
		c.InitialWindow = 32 * 1024
		c.MaxFramePayload = 8 * 1024
	})
	ctx := context.Background()

	const total = 4 << 20

	go func() {
		st, err := server.AcceptStream(ctx)
		if err != nil {
			return
		}
		defer func() { _ = st.Close() }()
		payload := make([]byte, 64*1024)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		for written := 0; written < total; {
			n := len(payload)
			if total-written < n {
				n = total - written
			}
			if _, err := st.Write(payload[:n]); err != nil {
				return
			}
			written += n
		}
	}()

	st, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Close(); err != nil { // we send nothing
		t.Fatalf("close write side: %v", err)
	}

	hasher := sha256.New()
	n, err := io.Copy(hasher, st)
	if err != nil {
		t.Fatalf("copy after %d bytes: %v", n, err)
	}
	if n != total {
		t.Fatalf("received %d bytes, want %d", n, total)
	}

	want := sha256.New()
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	for written := 0; written < total; written += len(payload) {
		k := len(payload)
		if total-written < k {
			k = total - written
		}
		want.Write(payload[:k])
	}
	if !bytes.Equal(hasher.Sum(nil), want.Sum(nil)) {
		t.Fatal("payload corrupted: correct length, wrong contents")
	}
}

func TestStreamLimitRefusesExtraStreams(t *testing.T) {
	client, server := pair(t, func(c *Config) { c.MaxStreams = 2 })
	ctx := context.Background()

	// Accept but never finish, so the streams stay open and occupy the limit.
	go func() {
		for {
			if _, err := server.AcceptStream(ctx); err != nil {
				return
			}
		}
	}()

	for i := 0; i < 2; i++ {
		if _, err := client.Open(ctx); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}

	_, err := client.Open(ctx)
	if err == nil {
		t.Fatal("opened a third stream with a limit of two")
	}
	if !errors.Is(err, ErrTooManyStreams) && !errors.Is(err, ErrStreamRefused) {
		t.Fatalf("err = %v, want a stream-limit error", err)
	}
}

func TestResetPropagatesReason(t *testing.T) {
	client, server := pair(t, nil)
	ctx := context.Background()

	go func() {
		st, err := server.AcceptStream(ctx)
		if err != nil {
			return
		}
		// The endpoint could not reach its target: abort, do not half-close.
		_ = st.Reset(proto.ReasonTargetConnectionRefused)
	}()

	st, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	buf := make([]byte, 16)
	_, err = st.Read(buf)
	if err == nil {
		t.Fatal("read succeeded on a reset stream")
	}
	// The reason must survive the trip, or the operator cannot tell an
	// unreachable target from a denial.
	if !bytes.Contains([]byte(err.Error()), []byte(proto.ReasonTargetConnectionRefused)) {
		t.Fatalf("err = %v, want it to carry %q", err, proto.ReasonTargetConnectionRefused)
	}
}

func TestSessionCloseUnblocksStreams(t *testing.T) {
	client, server := pair(t, nil)
	ctx := context.Background()

	go func() {
		if _, err := server.AcceptStream(ctx); err != nil {
			return
		}
	}()

	st, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	blocked := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := st.Read(buf)
		blocked <- err
	}()

	// A reader parked on a stream must not survive the session it belongs to.
	_ = client.Close(proto.ReasonShutdown)

	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("blocked read returned success after the session closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closing the session left a reader blocked forever")
	}
}

func TestKeepAliveDetectsDeadPeer(t *testing.T) {
	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := Config{
		MaxFramePayload: 4096,
		InitialWindow:   4096,
		MaxStreams:      2,
		KeepAlive:       50 * time.Millisecond,
		IdleTimeout:     150 * time.Millisecond,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	go func() {
		sc := cfg
		sc.Role = proto.RoleAgent
		h, err := Accept(ctx, transport.NewConn(s), sc)
		if err != nil {
			return
		}
		sess, err := h.Admit("ses_dead")
		if err != nil {
			return
		}
		// Go silent without closing: the shape of a peer whose host vanished.
		// Only the idle timeout can detect this.
		<-sess.Done()
	}()

	cc := cfg
	cc.Role = proto.RoleOperator
	client, err := Dial(ctx, transport.NewConn(c), cc, proto.Auth{DeviceID: "dev"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Stop the far end from answering pings by closing its socket underneath it.
	_ = s.Close()

	select {
	case <-client.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session survived a peer that stopped responding")
	}
}

func TestWrongParityRejected(t *testing.T) {
	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := Config{MaxFramePayload: 4096, InitialWindow: 4096, MaxStreams: 4,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	sessCh := make(chan *Session, 1)
	go func() {
		sc := cfg
		sc.Role = proto.RoleAgent
		h, err := Accept(ctx, transport.NewConn(s), sc)
		if err != nil {
			return
		}
		sess, err := h.Admit("ses_parity")
		if err == nil {
			sessCh <- sess
		}
	}()

	conn := transport.NewConn(c)
	cc := cfg
	cc.Role = proto.RoleOperator
	client, err := Dial(ctx, conn, cc, proto.Auth{DeviceID: "dev"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server := <-sessCh

	// The client owns odd IDs. Opening an even one invades the server's half of
	// the identifier space, where it could collide with a stream the server is
	// about to open.
	if err := conn.W.WriteFrame(proto.TypeOpenStream, 2, nil); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case <-server.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("server accepted a stream id from the wrong half of the space")
	}
	_ = client.Close(proto.ReasonShutdown)
}
