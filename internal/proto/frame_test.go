package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
)

// TestHeaderLayout pins the exact byte layout. The wire format is a compatibility
// surface, so this test exists to fail loudly if someone reorders a field or
// changes endianness: those are the changes that silently break interop with an
// older peer rather than producing an obvious error.
func TestHeaderLayout(t *testing.T) {
	var buf [HeaderSize]byte
	encodeHeader(buf[:], TypeStreamData, 0x01020304, 0x0A0B0C0D)

	want := []byte{
		Version,                // offset 0: version
		byte(TypeStreamData),   // offset 1: type
		0x01, 0x02, 0x03, 0x04, // offset 2..5: stream_id, big-endian
		0x0A, 0x0B, 0x0C, 0x0D, // offset 6..9: length, big-endian
	}
	if !bytes.Equal(buf[:], want) {
		t.Fatalf("header layout changed\n got: % x\nwant: % x", buf[:], want)
	}
}

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		typ      Type
		streamID uint32
		payload  []byte
	}{
		{"empty payload", TypePing, 0, nil},
		{"small payload", TypeStreamData, 1, []byte("hello")},
		{"max payload", TypeStreamData, 7, bytes.Repeat([]byte{0xAB}, MaxFramePayload)},
		{"close with reason", TypeCloseStream, 3, []byte(ReasonOK)},
		{"high stream id", TypeStreamData, ^uint32(0), []byte("x")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf, MaxFramePayload)
			if err := w.WriteFrame(tc.typ, tc.streamID, tc.payload); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}

			r := NewReader(&buf, MaxFramePayload)
			got, err := r.ReadFrame()
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if got.Type != tc.typ {
				t.Errorf("type = %v, want %v", got.Type, tc.typ)
			}
			if got.StreamID != tc.streamID {
				t.Errorf("stream id = %d, want %d", got.StreamID, tc.streamID)
			}
			if !bytes.Equal(got.Payload, tc.payload) {
				t.Errorf("payload length = %d, want %d", len(got.Payload), len(tc.payload))
			}
		})
	}
}

// TestOversizedFrameRejectedBeforeAllocation is the security-relevant case: a
// peer declares a huge payload but sends nothing. The decoder must reject on the
// declared length alone, without waiting for bytes that will never arrive and
// without sizing an allocation from the claim.
func TestOversizedFrameRejectedBeforeAllocation(t *testing.T) {
	var hdr [HeaderSize]byte
	hdr[offVersion] = Version
	hdr[offType] = byte(TypeStreamData)
	binary.BigEndian.PutUint32(hdr[offStreamID:], 1)
	binary.BigEndian.PutUint32(hdr[offLength:], ^uint32(0)) // claim ~4 GiB

	// Only the header is present. If the decoder tried to read the payload first,
	// this would block or fail with EOF instead of the limit error.
	r := NewReader(bytes.NewReader(hdr[:]), MaxFramePayload)

	_, err := r.ReadFrame()
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
	if got := ReasonFor(err); got != ReasonLimitFrameTooLarge {
		t.Errorf("reason = %q, want %q", got, ReasonLimitFrameTooLarge)
	}
}

func TestTruncatedPayloadIsMalformedNotEOF(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, MaxFramePayload)
	if err := w.WriteFrame(TypeStreamData, 1, []byte("0123456789")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Drop the last three payload bytes: the header still promises ten.
	truncated := buf.Bytes()[:buf.Len()-3]

	r := NewReader(bytes.NewReader(truncated), MaxFramePayload)
	_, err := r.ReadFrame()
	if !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("err = %v, want ErrMalformedFrame", err)
	}
	// A peer that stops mid-payload must not look like an orderly close, or a
	// truncation attack is indistinguishable from a normal disconnect.
	if errors.Is(err, io.EOF) {
		t.Error("truncated payload reported as EOF")
	}
}

func TestUnknownTypeRejected(t *testing.T) {
	var hdr [HeaderSize]byte
	hdr[offVersion] = Version
	hdr[offType] = 0x55 // not a defined type
	binary.BigEndian.PutUint32(hdr[offStreamID:], 1)
	binary.BigEndian.PutUint32(hdr[offLength:], 0)

	r := NewReader(bytes.NewReader(hdr[:]), MaxFramePayload)
	_, err := r.ReadFrame()
	if !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("err = %v, want ErrMalformedFrame", err)
	}
}

func TestUnsupportedVersionRejected(t *testing.T) {
	var hdr [HeaderSize]byte
	hdr[offVersion] = Version + 1
	hdr[offType] = byte(TypeStreamData)
	binary.BigEndian.PutUint32(hdr[offStreamID:], 1)
	binary.BigEndian.PutUint32(hdr[offLength:], 0)

	r := NewReader(bytes.NewReader(hdr[:]), MaxFramePayload)
	_, err := r.ReadFrame()
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("err = %v, want ErrUnsupportedVersion", err)
	}
	if got := ReasonFor(err); got != ReasonProtocolVersionUnsupported {
		t.Errorf("reason = %q, want %q", got, ReasonProtocolVersionUnsupported)
	}
}

func TestWriteRejectsOversizedPayload(t *testing.T) {
	w := NewWriter(io.Discard, 16)
	err := w.WriteFrame(TypeStreamData, 1, bytes.Repeat([]byte{0}, 17))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
}

func TestCleanEOFIsEOF(t *testing.T) {
	// Nothing at all on the wire is an orderly close and must stay io.EOF, so
	// callers can distinguish "peer went away" from "peer sent nonsense".
	r := NewReader(bytes.NewReader(nil), MaxFramePayload)
	if _, err := r.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

// TestConcurrentWritesDoNotInterleave exercises the Writer mutex. Without it,
// two goroutines writing frames would interleave header and payload bytes and
// corrupt the stream. Run with -race for the full effect.
func TestConcurrentWritesDoNotInterleave(t *testing.T) {
	const (
		writers          = 8
		framesPerWriter  = 64
		payloadSizeBytes = 512
	)

	var buf lockedBuffer
	w := NewWriter(&buf, MaxFramePayload)

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Each writer emits a payload of a single distinct byte value, so an
			// interleaving shows up as a frame with mixed contents.
			payload := bytes.Repeat([]byte{byte('A' + id)}, payloadSizeBytes)
			for j := 0; j < framesPerWriter; j++ {
				if err := w.WriteFrame(TypeStreamData, uint32(id), payload); err != nil {
					t.Errorf("writer %d: %v", id, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	r := NewReader(bytes.NewReader(buf.Bytes()), MaxFramePayload)
	for n := 0; n < writers*framesPerWriter; n++ {
		f, err := r.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", n, err)
		}
		want := bytes.Repeat([]byte{byte('A' + f.StreamID)}, payloadSizeBytes)
		if !bytes.Equal(f.Payload, want) {
			t.Fatalf("frame %d from stream %d has mixed contents: writes interleaved", n, f.StreamID)
		}
	}
}

// TestPayloadAliasingContract documents the buffer-reuse rule by demonstrating
// it. A payload is valid only until the next read on the same Reader; this test
// exists so the behaviour is deliberate and visible rather than something a
// future reader debugs from first principles.
func TestPayloadAliasingContract(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, MaxFramePayload)
	if err := w.WriteFrame(TypeStreamData, 1, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFrame(TypeStreamData, 1, []byte("second")); err != nil {
		t.Fatal(err)
	}

	r := NewReader(&buf, MaxFramePayload)
	first, err := r.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	retained := first.Payload // deliberately kept across the next read

	if _, err := r.ReadFrame(); err != nil {
		t.Fatal(err)
	}

	// retained still points at the Reader's buffer, which now holds the second
	// frame. It keeps its original length, so it shows a prefix of the new data.
	// Callers that need bytes to outlive the next read must copy them.
	want := "second"[:len(retained)]
	if string(retained) != want {
		t.Fatalf("retained = %q, want %q: buffer was expected to be reused", retained, want)
	}
}

// lockedBuffer is a bytes.Buffer safe for concurrent writers. The Writer mutex
// serialises whole frames, but the underlying io.Writer still sees calls from
// several goroutines, and bytes.Buffer is not itself concurrency-safe.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Bytes()
}
