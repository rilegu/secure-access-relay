// Package httpapi serves the control-plane HTTP interface.
//
// It carries enrollment, operator login, and grant issuance. It is separate from
// the relay's data plane on purpose: the control plane decides who may exist and
// what they may reach, the relay carries bytes for peers that already do, and
// keeping them apart is what lets them be deployed and hardened separately
// later — see docs/decisions/0007.
//
// # What this package must never do
//
//   - It must never carry payload traffic.
//   - It must never return an error string that reveals internal state to an
//     unauthenticated caller.
package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/control/enrollment"
	"github.com/rilegu/secure-access-relay/internal/control/grants"
	"github.com/rilegu/secure-access-relay/internal/control/login"
	"github.com/rilegu/secure-access-relay/internal/control/policy"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// maxRequestBody bounds an enrollment request.
//
// A certificate request is a few hundred bytes. The limit exists because this
// endpoint is reachable by anyone who can route to it, and an unbounded read from
// an unauthenticated caller is a way to consume memory for free.
const maxRequestBody = 16 << 10

// Server is the control-plane HTTP server.
type Server struct {
	enroll *enrollment.Service
	issuer *grants.Issuer
	verify *enrollment.Service
	login  *login.Service
	audit  *audit.Recorder
	rules  RulesFunc
	log    *slog.Logger

	// terminate drops the live streams a set of revoked grants authorized.
	//
	// A function rather than a reference to the relay, so the control plane does
	// not import it. The dependency runs one way: the control plane decides, the
	// relay is told, and the relay never calls back.
	terminate TerminateFunc

	srv   *http.Server
	ln    net.Listener
	ready chan struct{}
}

// TerminateFunc drops every live stream opened under any of the named grants.
type TerminateFunc func(grantIDs []string)

// Config configures the control-plane server.
type Config struct {
	Addr string
	// TLS is required. Enrollment carries a token that grants an identity, and
	// carrying it in the clear would hand it to anyone on the path.
	TLS *tls.Config

	// Issuer signs grants. Optional: without it the grants route reports that it
	// is not configured rather than silently accepting requests it cannot serve.
	Issuer *grants.Issuer

	// Rules supplies the policy rule set for each request.
	Rules RulesFunc

	// Login issues and ends operator sessions. When it is set, a grant request
	// must carry a live session; when it is nil, the login routes report that
	// sessions are not configured and grants are issued on the certificate alone.
	Login *login.Service

	// Audit records events that are not already written inside a transaction by
	// the component that caused them.
	Audit *audit.Recorder

	// Terminate drops live streams when a grant is revoked. Without it a
	// revocation still stops new streams but leaves running ones alone, which is
	// the gap revocation exists to close — so its absence is logged at startup.
	Terminate TerminateFunc

	Logger *slog.Logger
}

// New creates the control-plane server.
func New(cfg Config, enroll *enrollment.Service) (*Server, error) {
	if cfg.TLS == nil {
		return nil, errors.New("httpapi: refusing to serve enrollment without TLS")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	rules := cfg.Rules
	if rules == nil {
		// No rule source means no rules, and no rules means every request is
		// denied. That is the correct default for an authorization system.
		rules = func() []policy.Rule { return nil }
	}

	s := &Server{
		enroll:    enroll,
		issuer:    cfg.Issuer,
		verify:    enroll,
		login:     cfg.Login,
		audit:     cfg.Audit,
		rules:     rules,
		terminate: cfg.Terminate,
		log:       cfg.Logger,
		ready:     make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /v1/login", s.handleLogin)
	mux.HandleFunc("POST /v1/logout", s.handleLogout)
	mux.HandleFunc("POST /v1/grants", s.handleGrant)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})

	s.srv = &http.Server{
		Addr:      cfg.Addr,
		Handler:   mux,
		TLSConfig: cfg.TLS,
		// Bounded so a peer cannot hold a connection open by sending headers one
		// byte at a time.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s, nil
}

// Run serves until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.srv.Addr, err)
	}
	s.ln = ln
	close(s.ready)

	s.log.Info("control plane listening", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
	}()

	// The certificate and key already live in TLSConfig.
	if err := s.srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return ctx.Err()
}

// Ready is closed once the listener is bound.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// Addr reports the bound address.
func (s *Server) Addr() string {
	if s.ln == nil {
		return s.srv.Addr
	}
	return s.ln.Addr().String()
}

// enrollRequest is what a peer sends to enroll.
type enrollRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

// enrollResponse is what it gets back.
type enrollResponse struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
	Identity    string `json:"identity"`
	NotAfter    string `json:"not_after"`
	// GrantKey is the base64 public key that verifies grants. Without it an
	// agent could authenticate but not authorize.
	GrantKey string `json:"grant_key"`
}

// handleEnroll consumes a token and issues a certificate.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}

	result, err := s.enroll.Enroll(req.Token, []byte(req.CSR))
	if err != nil {
		// Every token failure returns the same status and the same message.
		//
		// The distinction between "no such token", "already used", and "expired"
		// is useful to an operator and useful to an attacker probing for valid
		// tokens. The caller gets one answer; the log gets the real reason.
		switch {
		case errors.Is(err, storage.ErrTokenUnknown),
			errors.Is(err, storage.ErrTokenConsumed),
			errors.Is(err, storage.ErrTokenExpired):
			s.log.Warn("enrollment refused",
				"remote", r.RemoteAddr, "error", err.Error())
			// Recorded with a coarse reason, not the specific one. The caller is
			// told nothing that helps them tell a valid token from an invalid one,
			// and the trail records that somebody tried — which is the part worth
			// noticing when it happens repeatedly.
			s.recordEnrollDenied(r, "token_refused")
			writeError(w, http.StatusForbidden, "enrollment refused")
			return
		case errors.Is(err, enrollment.ErrInvalidCSR):
			s.log.Warn("enrollment csr rejected", "remote", r.RemoteAddr, "error", err.Error())
			s.recordEnrollDenied(r, "invalid_csr")
			writeError(w, http.StatusBadRequest, "invalid certificate request")
			return
		default:
			s.log.Error("enrollment failed", "remote", r.RemoteAddr, "error", err.Error())
			writeError(w, http.StatusInternalServerError, "enrollment failed")
			return
		}
	}

	s.log.Info("device enrolled",
		"identity", result.Identity.String(),
		"remote", r.RemoteAddr,
		"not_after", result.NotAfter.UTC().Format(time.RFC3339),
	)
	if s.audit != nil {
		s.audit.Enrolled(r.Context(), string(result.Identity.Role), result.Identity.ID,
			"from "+remoteHost(r)+", certificate valid until "+result.NotAfter.UTC().Format(time.RFC3339))
	}

	writeJSON(w, http.StatusOK, enrollResponse{
		Certificate: string(result.CertificatePEM),
		CA:          string(result.CAPEM),
		Identity:    result.Identity.String(),
		NotAfter:    result.NotAfter.UTC().Format(time.RFC3339),
		GrantKey:    base64.StdEncoding.EncodeToString(result.GrantPublicKey),
	})
}

// recordEnrollDenied records a refused enrollment.
//
// The token is never recorded, not even hashed. A refused attempt may carry a
// value the caller should not have had, and copying it into durable storage
// would preserve exactly the thing that should not be preserved.
func (s *Server) recordEnrollDenied(r *http.Request, reason string) {
	if s.audit == nil {
		return
	}
	s.audit.EnrollDenied(r.Context(), remoteHost(r), reason)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
