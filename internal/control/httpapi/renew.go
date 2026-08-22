package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/control/enrollment"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// renewRequest carries only a certificate request.
//
// No identity field, deliberately. Who is renewing comes from the certificate
// presented on the connection; a body that could name its own identity would let
// any enrolled peer mint a certificate for any other.
type renewRequest struct {
	CSR string `json:"csr"`
}

// handleRenew issues a fresh certificate to a peer that already holds a valid one.
//
// Authenticated by the certificate being replaced. That is the whole point: a
// fleet whose certificates expire after thirty days cannot depend on somebody
// minting an enrollment token for every endpoint before then, and the failure
// mode of forgetting is every agent going dark on the same day with no symptom
// beyond silence.
//
// Both roles may renew. An operator's certificate expires exactly as a device's
// does, and an operator who has to re-enroll mid-incident is an operator who
// cannot help.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.log.Warn("renewal without a client certificate", "remote", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "a client certificate is required")
		return
	}

	var req renewRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}

	result, err := s.enroll.Renew(r.TLS.PeerCertificates[0], []byte(req.CSR))
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrRevoked), errors.Is(err, storage.ErrNotEnrolled):
			// A revoked identity must not be able to renew its way back, and a
			// superseded certificate must not be able to mint a current one.
			s.log.Warn("renewal refused",
				"remote", r.RemoteAddr,
				"subject", r.TLS.PeerCertificates[0].Subject.CommonName,
				"error", err)
			s.recordRenewDenied(r, "not_recognised")
			writeError(w, http.StatusForbidden, "not recognised")
			return
		case errors.Is(err, enrollment.ErrInvalidCSR):
			s.log.Warn("renewal csr rejected", "remote", r.RemoteAddr, "error", err)
			s.recordRenewDenied(r, "invalid_csr")
			writeError(w, http.StatusBadRequest, "invalid certificate request")
			return
		default:
			s.log.Error("renewal failed", "remote", r.RemoteAddr, "error", err)
			writeError(w, http.StatusInternalServerError, "renewal failed")
			return
		}
	}

	s.log.Info("certificate renewed",
		"identity", result.Identity.String(),
		"remote", remoteHost(r),
		"not_after", result.NotAfter.UTC().Format(time.RFC3339),
	)
	if s.audit != nil {
		s.audit.Renewed(r.Context(), string(result.Identity.Role), result.Identity.ID,
			"from "+remoteHost(r)+", valid until "+result.NotAfter.UTC().Format(time.RFC3339))
	}

	writeJSON(w, http.StatusOK, enrollResponse{
		Certificate: string(result.CertificatePEM),
		CA:          string(result.CAPEM),
		Identity:    result.Identity.String(),
		NotAfter:    result.NotAfter.UTC().Format(time.RFC3339),
		GrantKey:    base64.StdEncoding.EncodeToString(result.GrantPublicKey),
	})
}

// recordRenewDenied records a refused renewal.
//
// Worth recording rather than only logging: a run of refused renewals is what a
// revoked endpoint that has not noticed looks like, and it is also what an
// attacker replaying a superseded certificate looks like.
func (s *Server) recordRenewDenied(r *http.Request, reason string) {
	if s.audit == nil {
		return
	}
	s.audit.Record(r.Context(), storage.AuditEvent{
		Event:     audit.EventRenewDenied,
		ActorRole: audit.RoleSystem,
		Reason:    reason,
		Detail:    "from " + remoteHost(r),
	})
}
