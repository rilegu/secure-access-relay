// Package policy decides whether an operator may reach a resource on a device.
//
// It is the only place in the system that answers that question. The relay
// forwards bytes, the agent enforces what a grant says, and neither decides
// anything — see docs/policy.md and invariant 2.
//
// # What this package must never do
//
//   - It must never default to allowing. An absent, unparsable, or empty rule
//     set denies everything.
//   - It must never depend on rule order. Rules are a union, evaluated as a set.
package policy

import (
	"time"

	"github.com/rilegu/secure-access-relay/internal/proto"
)

// Effect is what a rule does when it matches. Only allow exists.
//
// # Why there are no deny rules
//
// A deny rule that can override an allow makes evaluation order significant, and
// evaluation order is where authorization bugs live: two rules that are each
// correct produce a wrong answer depending on which is read first. With
// allow-only, the rule set is a union, order is irrelevant, and "is this
// allowed" has exactly one answer no matter how the rules are arranged.
//
// The cost is that carving an exception out of a broad grant is impossible. That
// is acceptable because grants here are not broad: a rule names specific devices
// and specific resources, with no wildcards.
type Effect string

// EffectAllow is the only supported effect.
const EffectAllow Effect = "allow"

// Rule maps principals to the resources they may reach on which devices.
//
// Every field is an explicit list. Wildcards are deliberately absent: a rule that
// can say "all devices" is a rule whose blast radius changes every time a device
// is enrolled, without anyone editing the rule.
type Rule struct {
	PolicyID string `json:"policy_id"`

	// Principals are user identifiers. Groups are not yet modelled, so this is
	// users only, and a rule with no principals matches nobody.
	Principals []string `json:"principals"`

	// Devices and Resources are matched exactly.
	Devices   []string `json:"devices"`
	Resources []string `json:"resources"`

	// MaxTTL caps the lifetime of grants issued under this rule. The effective
	// ceiling is the smallest of this, the request, and proto.MaxGrantTTL.
	MaxTTL Duration `json:"max_ttl"`

	Effect Effect `json:"effect"`
}

// Duration reads from JSON as "30m" rather than as a count of nanoseconds, for
// the same reason as the agent's resource file: limits should be checkable at a
// glance.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	return unmarshalDuration(b, (*time.Duration)(d))
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return marshalDuration(time.Duration(d))
}

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Decision is the outcome of evaluating a request.
type Decision struct {
	// Allowed is false unless some rule matched. There is no other way for it to
	// be true.
	Allowed bool

	// MaxTTL is the longest grant that may be issued for this request.
	MaxTTL time.Duration

	// PolicyID names the rule that allowed it, for the audit record. An
	// authorization that cannot say which rule permitted it is not auditable.
	PolicyID string

	// Reason explains a denial, using the same stable codes as the wire protocol.
	Reason proto.Reason
}

// Evaluate decides a request against a rule set.
//
// Deny by default: the function starts at denied and only a matching allow rule
// changes that. Every early return is a denial, which is the safe direction for
// a function that might be edited later by someone in a hurry.
//
// When several rules match, the most permissive TTL wins — the operator is
// entitled to the best of what they have been granted, and taking the minimum
// instead would make adding a narrow rule silently shorten access an existing
// broad rule already allowed.
func Evaluate(rules []Rule, userID, deviceID, resourceID string) Decision {
	denied := Decision{Allowed: false, Reason: proto.ReasonPolicyDenied}

	if userID == "" || deviceID == "" || resourceID == "" {
		// An incomplete request cannot match a rule that names all three. Refusing
		// explicitly avoids relying on an empty string failing to match by luck.
		return denied
	}

	best := denied
	for _, r := range rules {
		if r.Effect != EffectAllow {
			// An unrecognised effect is not a silent no-op: it is skipped, and
			// because the default is denial, an entirely unrecognised rule set
			// denies everything rather than allowing everything.
			continue
		}
		if !contains(r.Principals, userID) ||
			!contains(r.Devices, deviceID) ||
			!contains(r.Resources, resourceID) {
			continue
		}

		ttl := r.MaxTTL.Duration()
		if ttl <= 0 || ttl > proto.MaxGrantTTL {
			// A rule asking for more than the system ceiling gets the ceiling
			// rather than being rejected: the rule is over-optimistic, not
			// malformed, and silently capping is what the ceiling is for.
			ttl = proto.MaxGrantTTL
		}
		if !best.Allowed || ttl > best.MaxTTL {
			best = Decision{Allowed: true, MaxTTL: ttl, PolicyID: r.PolicyID, Reason: proto.ReasonOK}
		}
	}
	return best
}

// contains reports exact membership. No wildcards, no prefixes, no case folding:
// identifiers are opaque, and any normalisation here would be a way for two
// different identifiers to compare equal.
func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
