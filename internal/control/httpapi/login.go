package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/control/login"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// sessionHeader carries the bearer token on requests that need one.
//
// A header rather than a cookie: this is an API between two command-line tools,
// and a cookie would bring same-site and CSRF questions to a client that has no
// browser and no ambient authority to confuse.
const sessionHeader = "Authorization"

// bearerPrefix is the scheme the session token is presented under.
const bearerPrefix = "Bearer "

// loginRequest is what an operator sends. It is deliberately almost empty.
//
// There is no identity field. Who is logging in comes from the client
// certificate; a body that could name its own user would let anyone with any
// certificate open a session as anyone else.
type loginRequest struct {
	// TTLSeconds is a request, not an instruction. The service caps it.
	TTLSeconds int `json:"ttl_seconds"`
}

type loginResponse struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	ExpiresAt string `json:"expires_at"`
}

// handleLogin opens an operator session.
//
// The certificate is the authentication. This route does not add a second
// factor and does not pretend to — see the package doc of internal/control/login
// for what a session is actually for.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.login == nil {
		writeError(w, http.StatusNotImplemented, "sessions are not configured")
		return
	}

	id, ok := s.authenticateOperator(w, r, audit.EventOperatorLoginDenied)
	if !ok {
		return
	}

	// The body is optional: a client that wants the default lifetime sends none.
	var req loginRequest
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, maxRequestBody)).Decode(&req)
	}

	sess, err := s.login.Begin(r.Context(), id.ID, remoteHost(r))
	if err != nil {
		s.log.Error("could not open an operator session", "user_id", id.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "could not open a session")
		return
	}

	s.log.Info("operator session opened",
		"user_id", id.ID,
		"session_id", sess.Record.SessionID,
		"expires_at", sess.Record.ExpiresAt.Format(time.RFC3339),
		"remote", remoteHost(r),
	)

	writeJSON(w, http.StatusOK, loginResponse{
		Token:     sess.Token,
		SessionID: sess.Record.SessionID,
		UserID:    sess.Record.UserID,
		ExpiresAt: sess.Record.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

type logoutResponse struct {
	SessionID     string `json:"session_id"`
	GrantsRevoked int    `json:"grants_revoked"`
}

// handleLogout ends the caller's own session.
//
// Ending a session revokes the grants issued under it and drops the streams
// those grants opened. Anything less would mean an operator pressing logout
// keeps the access they already have, which is not what logout means anywhere
// else and should not mean it here.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.login == nil {
		writeError(w, http.StatusNotImplemented, "sessions are not configured")
		return
	}

	id, ok := s.authenticateOperator(w, r, "")
	if !ok {
		return
	}

	rec, err := s.login.Resolve(r.Context(), bearerToken(r))
	if err != nil {
		// Already gone is a success from the caller's point of view: they asked
		// for the session to be over, and it is.
		writeJSON(w, http.StatusOK, logoutResponse{})
		return
	}
	if rec.UserID != id.ID {
		// A valid token presented by a different certificate. That is either a
		// stolen token or a badly confused client, and neither should be able to
		// end somebody else's session.
		s.log.Warn("logout with a session belonging to another operator",
			"certificate_user", id.ID, "session_user", rec.UserID, "session_id", rec.SessionID)
		writeError(w, http.StatusForbidden, "not your session")
		return
	}

	revoked, err := s.login.End(r.Context(), rec.SessionID, id.ID, login.ReasonLogout)
	if err != nil {
		s.log.Error("logout failed", "session_id", rec.SessionID, "error", err)
		writeError(w, http.StatusInternalServerError, "could not end the session")
		return
	}

	// The relay drops the live streams. The database says the access is over;
	// this is what makes it over on the wire too.
	s.dropRevoked(revoked)

	s.log.Info("operator session ended",
		"user_id", id.ID, "session_id", rec.SessionID, "grants_revoked", len(revoked))

	writeJSON(w, http.StatusOK, logoutResponse{
		SessionID:     rec.SessionID,
		GrantsRevoked: len(revoked),
	})
}

// authenticateOperator resolves the client certificate to an enrolled operator.
//
// Every failure returns the same shape to the caller and the real reason to the
// log. If deniedEvent is non-empty, refusals are recorded in the audit trail —
// a run of them is how somebody notices a certificate being probed.
func (s *Server) authenticateOperator(w http.ResponseWriter, r *http.Request, deniedEvent string) (ca.Identity, bool) {
	deny := func(status int, msg, reason string) {
		if deniedEvent != "" && s.audit != nil {
			s.audit.Record(r.Context(), storage.AuditEvent{
				Event:     deniedEvent,
				ActorRole: audit.RoleSystem,
				Reason:    reason,
				Detail:    "from " + remoteHost(r),
			})
		}
		writeError(w, status, msg)
	}

	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.log.Warn("request without a client certificate", "remote", r.RemoteAddr, "path", r.URL.Path)
		deny(http.StatusUnauthorized, "a client certificate is required", "no_certificate")
		return ca.Identity{}, false
	}

	id, err := s.verify.VerifyEnrolled(r.TLS.PeerCertificates[0])
	if err != nil {
		s.log.Warn("request from an unrecognised identity",
			"remote", r.RemoteAddr, "path", r.URL.Path, "error", err)
		deny(http.StatusForbidden, "not recognised", "not_enrolled")
		return ca.Identity{}, false
	}
	if id.Role != ca.RoleOperator {
		// A device certificate asking for an operator route. Devices serve
		// resources; they do not request access to them.
		s.log.Warn("operator route used by a non-operator", "identity", id.String(), "path", r.URL.Path)
		deny(http.StatusForbidden, "not an operator", "not_an_operator")
		return ca.Identity{}, false
	}
	return id, true
}

// requireSession resolves the bearer token to a live session belonging to the
// authenticated operator.
//
// Returning the session rather than a boolean is deliberate: the caller needs
// the identifier to stamp on the grant, and an authorization check whose result
// is discarded is a check somebody eventually removes.
func (s *Server) requireSession(w http.ResponseWriter, r *http.Request, id ca.Identity) (storage.SessionRecord, bool) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "a session is required; run login first")
		return storage.SessionRecord{}, false
	}

	rec, err := s.login.Resolve(r.Context(), token)
	switch {
	case err == nil:
	case errors.Is(err, storage.ErrSessionExpired):
		// The distinct message is the point. An operator whose session simply ran
		// out should log in again; one whose session was cut short should find out
		// that somebody did that.
		writeError(w, http.StatusUnauthorized, "session expired; run login again")
		return storage.SessionRecord{}, false
	case errors.Is(err, storage.ErrSessionRevoked):
		s.log.Warn("grant request under a revoked session",
			"user_id", id.ID, "session_id", rec.SessionID)
		writeError(w, http.StatusForbidden, "session was revoked")
		return storage.SessionRecord{}, false
	default:
		writeError(w, http.StatusUnauthorized, "session not recognised")
		return storage.SessionRecord{}, false
	}

	if rec.UserID != id.ID {
		// The certificate and the token disagree about who is calling. One of them
		// was stolen; refuse and say nothing useful about which.
		s.log.Warn("session token does not match the presenting certificate",
			"certificate_user", id.ID, "session_user", rec.UserID, "session_id", rec.SessionID)
		writeError(w, http.StatusForbidden, "session not recognised")
		return storage.SessionRecord{}, false
	}
	return rec, true
}

// bearerToken extracts the session token from the Authorization header.
func bearerToken(r *http.Request) string {
	v := r.Header.Get(sessionHeader)
	if len(v) <= len(bearerPrefix) || !strings.EqualFold(v[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(v[len(bearerPrefix):])
}

// remoteHost strips the port from a remote address.
//
// The port is ephemeral and changes every connection, so keeping it would make
// two logins from the same machine look like two different places.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// dropRevoked asks the relay to terminate the streams a set of revoked grants
// authorized.
//
// The control plane records the decision; the relay owns the connections. This
// is the one call across that boundary, and it is one-way: the relay never tells
// the control plane what to do.
func (s *Server) dropRevoked(revoked []storage.GrantRecord) {
	if s.terminate == nil || len(revoked) == 0 {
		return
	}
	ids := make([]string, 0, len(revoked))
	for _, g := range revoked {
		ids = append(ids, g.GrantID)
	}
	s.terminate(ids)
}
