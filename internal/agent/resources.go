package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Resource is one named local service this agent is willing to reach.
//
// Resources are declared **on the agent**, never by the operator. An operator
// names a resource identifier and the agent resolves it here; the address never
// crosses the wire in either direction. That asymmetry is what makes this a
// resource proxy rather than a tunnel with an authentication step, and it means
// an authorization bug cannot become "reach anything you can name".
type Resource struct {
	// ResourceID is what a grant names. It is matched exactly.
	ResourceID string `json:"resource_id"`

	// Name is a human label for logs and operator output.
	Name string `json:"name"`

	// Protocol must be "tcp". Declared explicitly so that adding another later
	// is a deliberate change rather than a default that quietly widened.
	Protocol string `json:"protocol"`

	// Target is the loopback address to dial. A literal IP with an explicit
	// port; never a hostname.
	Target string `json:"target"`

	// MaxBytes caps one session's transfer. Zero means unlimited, which is
	// permitted but worth stating in configuration rather than defaulting to.
	MaxBytes uint64 `json:"max_bytes"`

	// MaxDuration caps one session's length, independently of the grant's TTL.
	// The shorter of the two applies.
	MaxDuration Duration `json:"max_duration"`
}

// Duration is a time.Duration that reads from JSON as "30m" rather than as a
// count of nanoseconds.
//
// Configuration is written by people. A resource limit expressed as
// 1800000000000 is a number nobody can check at a glance, and a limit nobody
// checks is a limit nobody notices is wrong.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30m\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Allowlist is the set of resources an agent will serve, keyed by resource ID.
type Allowlist map[string]Resource

// ErrResourceUnknown means no resource with that identifier is declared.
var ErrResourceUnknown = errors.New("agent: resource is not in the local allowlist")

// LoadAllowlist reads and validates a resource file.
//
// Every rule below is enforced here, at load, and a violation prevents the agent
// from starting at all. That is invariant 4: a misconfigured allowlist must never
// produce a running agent. Deferring these checks to stream time would mean a
// typo in configuration surfaces during an incident rather than during a
// deployment.
func LoadAllowlist(path string) (Allowlist, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read resources: %w", err)
	}

	var declared []Resource
	dec := json.NewDecoder(bytes.NewReader(b))
	// Unknown fields are an error rather than being ignored. A misspelled
	// "max_bytes" that is silently dropped is a limit the operator believes is
	// in force and is not.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&declared); err != nil {
		return nil, fmt.Errorf("parse resources in %s: %w", path, err)
	}

	list := make(Allowlist, len(declared))
	for i, r := range declared {
		if err := validateResource(r); err != nil {
			return nil, fmt.Errorf("resource %d (%q): %w", i, r.ResourceID, err)
		}
		if _, dup := list[r.ResourceID]; dup {
			// A duplicate identifier means two resources disagree about what a
			// grant refers to. Whichever won would be arbitrary.
			return nil, fmt.Errorf("resource %q is declared more than once", r.ResourceID)
		}
		list[r.ResourceID] = r
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%s declares no resources; an agent with nothing to serve will refuse every stream", path)
	}
	return list, nil
}

func validateResource(r Resource) error {
	if r.ResourceID == "" {
		return errors.New("resource_id is required")
	}
	if r.Protocol != "tcp" {
		return fmt.Errorf("protocol %q is not supported; only \"tcp\"", r.Protocol)
	}
	// The same check the single-target configuration used, applied per resource.
	// Literal loopback only, explicit port, no name resolution — see ValidateTarget.
	if err := ValidateTarget(r.Target); err != nil {
		return err
	}
	if d := r.MaxDuration.Duration(); d < 0 {
		return fmt.Errorf("max_duration %s is negative", d)
	}
	return nil
}

// Lookup resolves a resource identifier.
//
// The loopback rule is checked again here, not only at load. Configuration can be
// reloaded, and the invariant has to hold at the moment of use rather than only
// at the moment it was last read.
func (a Allowlist) Lookup(resourceID string) (Resource, error) {
	r, ok := a[resourceID]
	if !ok {
		return Resource{}, fmt.Errorf("%w: %q", ErrResourceUnknown, resourceID)
	}
	if err := ValidateTarget(r.Target); err != nil {
		return Resource{}, err
	}
	return r, nil
}

// IDs lists the declared resource identifiers, for startup logging so an
// operator can see what an agent is offering.
func (a Allowlist) IDs() []string {
	out := make([]string, 0, len(a))
	for id := range a {
		out = append(out, id)
	}
	return out
}
