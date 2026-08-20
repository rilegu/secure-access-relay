package operator

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rilegu/secure-access-relay/internal/proto"
)

// grantRefreshMargin is how long before expiry a cached grant is replaced.
//
// A grant handed to a stream must survive long enough to be useful. Using one
// with two seconds left would open a session that dies almost immediately, which
// looks to an operator like an unreliable system rather than like an expiring
// authorization.
const grantRefreshMargin = 60 * time.Second

// grantCache holds the current grant and replaces it as it ages.
//
// Cached rather than requested per stream because a browser opens several
// connections for one page, and asking the control plane six times for six
// identical authorizations is noise in the audit trail as well as latency.
type grantCache struct {
	mu      sync.Mutex
	encoded []byte
	grant   *proto.SignedGrant
}

// get returns a usable grant, requesting a new one when the cached one is
// missing or close to expiry.
func (f *Forwarder) grant(ctx context.Context) ([]byte, error) {
	f.grants.mu.Lock()
	defer f.grants.mu.Unlock()

	if g := f.grants.grant; g != nil && g.Remaining(time.Now()) > grantRefreshMargin {
		return f.grants.encoded, nil
	}

	encoded, signed, err := f.requestGrant(ctx)
	if err != nil {
		return nil, err
	}
	f.grants.encoded, f.grants.grant = encoded, signed

	f.log.Info("grant issued",
		"grant_id", signed.GrantID,
		"device_id", signed.DeviceID,
		"resource_id", signed.ResourceID,
		"expires_at", signed.ExpiresAt.Format(time.RFC3339),
	)
	return encoded, nil
}

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
	Error     string `json:"error"`
}

// requestGrant asks the control plane for authorization.
//
// The operator authenticates with its enrolled certificate, so the control plane
// establishes who is asking rather than being told. Nothing in the request body
// names the user, and there is no field for a target address.
func (f *Forwarder) requestGrant(ctx context.Context) ([]byte, *proto.SignedGrant, error) {
	if f.cfg.ControlAddr == "" {
		return nil, nil, fmt.Errorf("operator: no control-plane address configured; cannot obtain a grant")
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{f.cfg.Identity.Certificate},
				RootCAs:      f.cfg.Identity.CAPool,
				ServerName:   f.serverName(),
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	body, err := json.Marshal(grantRequest{
		DeviceID:   f.cfg.DeviceID,
		ResourceID: f.cfg.Resource,
		TTLSeconds: int(f.cfg.GrantTTL.Seconds()),
	})
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+f.cfg.ControlAddr+"/v1/grants", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request grant: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out grantResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("decode grant response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return nil, nil, fmt.Errorf("grant refused: %s", out.Error)
		}
		return nil, nil, fmt.Errorf("grant refused: status %d", resp.StatusCode)
	}

	encoded, err := base64.StdEncoding.DecodeString(out.Grant)
	if err != nil {
		return nil, nil, fmt.Errorf("decode grant: %w", err)
	}

	// Decoded and verified locally before use. The control plane is trusted to
	// decide, not to be correct: a grant that does not verify here would be
	// refused by the agent anyway, and finding out now produces a clear error
	// instead of a stream that is rejected for reasons the operator cannot see.
	signed, err := proto.DecodeGrant(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("control plane returned an unusable grant: %w", err)
	}
	if f.cfg.Identity.GrantKey != nil {
		if err := signed.Verify(f.cfg.Identity.GrantKey, time.Now(), signed.DeviceID); err != nil {
			return nil, nil, fmt.Errorf("control plane returned a grant that does not verify: %w", err)
		}
	}
	return encoded, signed, nil
}
