package operator

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rilegu/secure-access-relay/internal/identity"
	"github.com/rilegu/secure-access-relay/internal/keystore"
)

// sessionFile is where a session is cached, next to the operator's certificate.
const sessionFile = "session.json"

// sessionRefreshMargin is how close to expiry a cached session is abandoned.
//
// A session with a minute left would be used to request a grant that outlives
// it, and the next request would fail for a reason the operator has no way to
// connect to the one before.
const sessionRefreshMargin = 2 * time.Minute

// ErrNoSession means no usable session is stored.
var ErrNoSession = errors.New("operator: no active session; run login")

// controlResponse is satisfied by every control-plane reply this file decodes,
// so the error message can be read back without a type switch over anonymous
// structs.
type controlResponse interface {
	// errorMessage returns the control plane's own message, or empty if it gave
	// none. Its message is preferred over a status code because it is written to
	// be read by an operator.
	errorMessage() string
}

// loginReply is the body of a successful or refused login.
type loginReply struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	ExpiresAt string `json:"expires_at"`
	Error     string `json:"error"`
}

func (r *loginReply) errorMessage() string { return r.Error }

// logoutReply is the body of a logout.
type logoutReply struct {
	SessionID     string `json:"session_id"`
	GrantsRevoked int    `json:"grants_revoked"`
	Error         string `json:"error"`
}

func (r *logoutReply) errorMessage() string { return r.Error }

// Session is an operator's live session as the client sees it.
type Session struct {
	// Token is the bearer value. Sealed at rest — on Windows through DPAPI, the
	// same protection the private key gets — because a session token is a
	// credential, not a preference.
	Token string `json:"token"`

	SessionID string    `json:"session_id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`

	// ControlAddr is recorded so a session is not presented to a control plane
	// that never issued it. Different deployments issue tokens that look
	// identical, and sending one to the wrong place would leak it.
	ControlAddr string `json:"control_addr"`
}

// Usable reports whether a session is worth presenting.
func (s Session) Usable(controlAddr string) bool {
	return s.Token != "" &&
		s.ControlAddr == controlAddr &&
		time.Until(s.ExpiresAt) > sessionRefreshMargin
}

// Login opens a session with the control plane.
//
// The client certificate authenticates. This is not a second factor and does not
// pretend to be one — see internal/control/login for what a session is for.
func Login(ctx context.Context, id *identity.Identity, controlAddr, serverName string, ttl time.Duration) (Session, error) {
	body, err := json.Marshal(map[string]int{"ttl_seconds": int(ttl.Seconds())})
	if err != nil {
		return Session{}, err
	}

	var out loginReply
	if err := postControl(ctx, id, controlAddr, serverName, "/v1/login", "", body, &out); err != nil {
		return Session{}, err
	}

	expires, err := time.Parse(time.RFC3339, out.ExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("control plane returned an unparseable expiry %q: %w", out.ExpiresAt, err)
	}
	return Session{
		Token:       out.Token,
		SessionID:   out.SessionID,
		UserID:      out.UserID,
		ExpiresAt:   expires,
		ControlAddr: controlAddr,
	}, nil
}

// Logout ends a session and reports how many grants it revoked.
//
// The count is worth showing: it is the difference between logging out of a
// system that forgets you and logging out of one that also takes back the access
// you were given.
func Logout(ctx context.Context, id *identity.Identity, controlAddr, serverName string, sess Session) (int, error) {
	var out logoutReply
	if err := postControl(ctx, id, controlAddr, serverName, "/v1/logout", sess.Token, nil, &out); err != nil {
		return 0, err
	}
	return out.GrantsRevoked, nil
}

// SaveSession writes a session to the state directory, sealed.
//
// Sealed for the same reason the private key is: it is a bearer credential, and
// a file that grants access to customer endpoints should not be readable by
// anything that can read the operator's home directory.
func SaveSession(dir string, sess Session) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if _, err := keystore.Save(filepath.Join(dir, sessionFile), b); err != nil {
		return fmt.Errorf("store session: %w", err)
	}
	return nil
}

// LoadSession reads a stored session.
func LoadSession(dir string) (Session, error) {
	b, _, err := keystore.Load(filepath.Join(dir, sessionFile))
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return Session{}, ErrNoSession
		}
		return Session{}, err
	}
	var sess Session
	if err := json.Unmarshal(b, &sess); err != nil {
		// A session file that will not parse is discarded rather than repaired.
		// The cost is one login; the alternative is guessing at a credential.
		return Session{}, ErrNoSession
	}
	return sess, nil
}

// ClearSession removes a stored session.
//
// Called after logout so the file does not outlive the session it names. A stale
// token on disk is not usable, but it is a credential-shaped file that somebody
// will eventually try to explain.
func ClearSession(dir string) error {
	err := os.Remove(filepath.Join(dir, sessionFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// EnsureSession returns a usable session, opening one if the stored one is
// missing, stale, or for a different control plane.
//
// Opening one automatically is deliberate. A session is not a second factor, so
// requiring an explicit login before every forward would add a step without
// adding a check. What it would add is an operator who scripts around it.
func EnsureSession(ctx context.Context, id *identity.Identity, dir, controlAddr, serverName string, ttl time.Duration) (Session, error) {
	if sess, err := LoadSession(dir); err == nil && sess.Usable(controlAddr) {
		return sess, nil
	}

	sess, err := Login(ctx, id, controlAddr, serverName, ttl)
	if err != nil {
		return Session{}, err
	}
	if err := SaveSession(dir, sess); err != nil {
		// The session is live and usable; failing to cache it only means the next
		// command opens another one. Worth reporting, not worth failing.
		return sess, nil
	}
	return sess, nil
}

// postControl performs an authenticated control-plane request.
//
// One place, so the TLS configuration is written once: the operator's
// certificate, the enrollment authority as the only root, TLS 1.3, and the
// server name recorded at enrollment. There is no path here that skips
// verification.
func postControl(ctx context.Context, id *identity.Identity, controlAddr, serverName, path, token string, body []byte, out controlResponse) error {
	if controlAddr == "" {
		return errors.New("operator: no control-plane address configured")
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{id.Certificate},
				RootCAs:      id.CAPool,
				ServerName:   serverName,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader([]byte("{}"))
	} else {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+controlAddr+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("control plane request %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil && resp.StatusCode == http.StatusOK {
		return fmt.Errorf("decode response from %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		// The control plane's own message is preferred when it gave one: it is
		// written to be read by an operator, and replacing it with a status code
		// would discard the only useful part of the answer.
		if msg := out.errorMessage(); msg != "" {
			return fmt.Errorf("%s refused: %s", path, msg)
		}
		return fmt.Errorf("%s refused: status %d", path, resp.StatusCode)
	}
	return nil
}
