//go:build ignore

// httpfixture is the local service used to exercise the forwarding path by hand.
//
// It is not part of any binary. Files under testdata are ignored by the go tool,
// and the build tag keeps it out of any build that names it explicitly, so it
// can only be started deliberately:
//
//	go run ./testdata/fixtures/httpfixture.go
//
// It binds strictly to loopback. That is part of the demonstration rather than a
// detail: the point of the system is that an approved service stays unreachable
// from the network and is reached only through an authorized stream. A fixture
// listening on all interfaces would prove nothing.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "loopback address to listen on")
	flag.Parse()

	// Refuse to start on anything but loopback, for the reason in the package
	// comment: a fixture that can be reached directly undermines the thing it is
	// meant to demonstrate.
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("invalid address %q: %v", *addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatalf("refusing to listen on %q: fixture is loopback-only", *addr)
	}

	mux := http.NewServeMux()

	// /health is the golden-path probe.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","time":%q}`+"\n", time.Now().UTC().Format(time.RFC3339))
	})

	// /bytes/{n} returns n deterministic bytes and reports their digest in a
	// header, so a large transfer can be checked for integrity rather than just
	// for size. Corruption in the middle of a stream is the failure mode worth
	// catching, and a byte count alone would not notice it.
	mux.HandleFunc("/bytes/", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Path[len("/bytes/"):])
		if err != nil || n < 0 {
			http.Error(w, "usage: /bytes/{count}", http.StatusBadRequest)
			return
		}
		body := deterministicBytes(n)
		sum := sha256.Sum256(body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Content-SHA256", hex.EncodeToString(sum[:]))
		_, _ = w.Write(body)
	})

	// /echo returns the request body, to exercise the operator-to-agent direction
	// with a payload large enough to span several frames.
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		_, _ = io.Copy(w, r.Body)
	})

	// /slow dribbles a response out, to exercise a reader that is slower than the
	// writer feeding it.
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		for i := 0; i < 10; i++ {
			fmt.Fprintf(w, "chunk %d\n", i)
			flusher.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("fixture listening on %s (loopback only)", *addr)
	log.Fatal(srv.ListenAndServe())
}

// deterministicBytes returns n bytes of a repeating pattern. Deterministic so a
// caller can recompute the expected digest without holding the payload.
func deterministicBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251) // a prime stride, so the pattern does not align with frame boundaries
	}
	return b
}
