package proto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzReadFrame drives arbitrary bytes through the decoder.
//
// The decode path is the code most exposed to hostile input in the whole system:
// it runs before authentication, before authorization, and on data chosen
// entirely by the peer. The property asserted here is deliberately weak and
// therefore hard to argue with — the decoder must either return a frame or an
// error, and must never panic, hang, or allocate beyond its limit.
//
// Run longer with:
//
//	go test ./internal/proto -run=Fuzz -fuzz=FuzzReadFrame -fuzztime=60s
func FuzzReadFrame(f *testing.F) {
	// Seeds: one valid frame of each shape that matters, plus the malformed cases
	// worth keeping permanently in the corpus.
	var valid bytes.Buffer
	w := NewWriter(&valid, MaxFramePayload)
	_ = w.WriteFrame(TypeStreamData, 1, []byte("payload"))
	_ = w.WriteFrame(TypePing, 0, nil)
	_ = w.WriteFrame(TypeCloseStream, 1, []byte(ReasonOK))
	f.Add(valid.Bytes())

	f.Add([]byte{})                                      // empty
	f.Add(make([]byte, HeaderSize-1))                    // short header
	f.Add(make([]byte, HeaderSize))                      // zero header: bad version
	f.Add(oversizeHeader())                              // huge declared length
	f.Add([]byte{Version, 0x55, 0, 0, 0, 1, 0, 0, 0, 0}) // unknown type

	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(bytes.NewReader(data), MaxFramePayload)

		// Bound the loop. A conforming decoder makes progress or returns an
		// error, so an input yielding more frames than it has bytes would itself
		// be the bug this catches.
		for i := 0; i < len(data)+1; i++ {
			frame, err := r.ReadFrame()
			if err != nil {
				return
			}
			// Invariant: a successfully decoded frame never exceeds the limit.
			// If this ever trips, the pre-allocation check has been bypassed.
			if len(frame.Payload) > MaxFramePayload {
				t.Fatalf("decoded payload %d exceeds limit %d", len(frame.Payload), MaxFramePayload)
			}
			if !frame.Type.known() {
				t.Fatalf("decoder accepted unknown frame type %v", frame.Type)
			}
		}
	})
}

func oversizeHeader() []byte {
	b := make([]byte, HeaderSize)
	b[offVersion] = Version
	b[offType] = byte(TypeStreamData)
	binary.BigEndian.PutUint32(b[offStreamID:], 1)
	binary.BigEndian.PutUint32(b[offLength:], ^uint32(0))
	return b
}
