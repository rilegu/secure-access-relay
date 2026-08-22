package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/control/grants"
	"github.com/rilegu/secure-access-relay/internal/control/policy"
	"github.com/rilegu/secure-access-relay/internal/proto"
)

// grantRequest is what an operator asks for.
//
// Note what is absent: an address. An operator names a device and a resource,
// and the agent resolves the resource against its own allowlist. There is
// deliberately no field here that could carry a destination.
type grantRequest struct {
	DeviceID   string `json:"device_id"`
	ResourceID string `json:"resource_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type grantResponse struct {
	Grant     string `json:"grant"`
	GrantID   string `json:"grant_id"`
	ExpiresAt string `json:"expires_at"`
	PolicyID  string `json:"policy_id"`

	// SessionID is the session the grant was issued under, echoed so an operator
	// can quote it when asking for their own access to be cut short.
	SessionID string `json:"session_id,omitempty"`
}

// handleGrant issues a grant to an authenticated operator.
//
// The operator's identity comes from the client certificate, never from the
// request body. A request that could name its own user would let anyone with a
// certificate request a grant as anyone else, which would make policy
// meaningless.
func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request) {
	if s.issuer == nil {
		writeError(w, http.StatusNotImplemented, "grants are not configured")
		return
	}

	// A client certificate is required on this route. Enrollment cannot require
	// one — a peer enrolls precisely because it has none — so the TLS
	// configuration verifies a certificate if given and each route decides.
	id, ok := s.authenticateOperator(w, r, audit.EventGrantDenied)
	if !ok {
		return
	}

	// A live session is required whenever the deployment has one configured. The
	// session is not a second authentication factor; it is what makes the grant
	// revocable as a group and attributable to a period of work.
	var sessionID string
	if s.login != nil {
		sess, ok := s.requireSession(w, r, id)
		if !ok {
			return
		}
		sessionID = sess.SessionID
	}

	var req grantRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = proto.MaxGrantTTL
	}

	signed, decision, err := s.issuer.Issue(r.Context(), s.rules(), grants.Request{
		UserID:       id.ID,
		DeviceID:     req.DeviceID,
		ResourceID:   req.ResourceID,
		RequestedTTL: ttl,
		SessionID:    sessionID,
	})
	if err != nil {
		if errors.Is(err, grants.ErrDenied) {
			// Logged with everything needed to answer "why was I denied", because
			// this is the record an operator will ask about. The caller is told
			// only that it was denied. The audit event is written by the issuer,
			// inside the same call that made the decision.
			s.log.Info("grant denied",
				"user_id", id.ID,
				"device_id", req.DeviceID,
				"resource_id", req.ResourceID,
				"session_id", sessionID,
				"reason", decision.Reason.String(),
			)
			writeError(w, http.StatusForbidden, string(proto.ReasonPolicyDenied))
			return
		}
		s.log.Error("grant issuance failed", "user_id", id.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "could not issue a grant")
		return
	}

	s.log.Info("grant issued",
		"grant_id", signed.GrantID,
		"user_id", signed.UserID,
		"device_id", signed.DeviceID,
		"resource_id", signed.ResourceID,
		"policy_id", decision.PolicyID,
		"session_id", sessionID,
		"expires_at", signed.ExpiresAt.Format(time.RFC3339),
	)

	writeJSON(w, http.StatusOK, grantResponse{
		Grant:     base64.StdEncoding.EncodeToString(signed.Encode()),
		GrantID:   signed.GrantID,
		ExpiresAt: signed.ExpiresAt.UTC().Format(time.RFC3339),
		PolicyID:  decision.PolicyID,
		SessionID: sessionID,
	})
}

// RulesFunc supplies the current policy rule set.
//
// A function rather than a slice so that reloading policy later does not require
// restarting the server, and so the server never holds a stale copy.
type RulesFunc func() []policy.Rule
