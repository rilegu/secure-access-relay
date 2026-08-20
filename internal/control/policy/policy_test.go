package policy

import (
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/proto"
)

func rules() []Rule {
	return []Rule{
		{
			PolicyID:   "pol_support",
			Principals: []string{"usr_maria"},
			Devices:    []string{"dev_panel_01"},
			Resources:  []string{"res_diagnostics"},
			MaxTTL:     Duration(20 * time.Minute),
			Effect:     EffectAllow,
		},
	}
}

func TestAllowsExactMatch(t *testing.T) {
	d := Evaluate(rules(), "usr_maria", "dev_panel_01", "res_diagnostics")
	if !d.Allowed {
		t.Fatal("an exact match was denied")
	}
	if d.MaxTTL != 20*time.Minute {
		t.Errorf("ttl = %s, want 20m", d.MaxTTL)
	}
	if d.PolicyID != "pol_support" {
		t.Errorf("policy id = %q; an allow must name the rule that permitted it", d.PolicyID)
	}
}

// TestDeniesByDefault enumerates the ways a request can miss.
//
// Wrong user, wrong device, and wrong resource are three different authorization
// failures, and all three must fail closed. They are listed separately rather
// than generated, so that removing one is a visible edit.
func TestDeniesByDefault(t *testing.T) {
	cases := map[string][3]string{
		"wrong user":     {"usr_someone_else", "dev_panel_01", "res_diagnostics"},
		"wrong device":   {"usr_maria", "dev_other_panel", "res_diagnostics"},
		"wrong resource": {"usr_maria", "dev_panel_01", "res_something_else"},
		"empty user":     {"", "dev_panel_01", "res_diagnostics"},
		"empty device":   {"usr_maria", "", "res_diagnostics"},
		"empty resource": {"usr_maria", "dev_panel_01", ""},
		"all empty":      {"", "", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := Evaluate(rules(), c[0], c[1], c[2])
			if d.Allowed {
				t.Fatalf("%s was allowed", name)
			}
			if d.Reason != proto.ReasonPolicyDenied {
				t.Errorf("reason = %q, want %q", d.Reason, proto.ReasonPolicyDenied)
			}
		})
	}
}

func TestEmptyRuleSetDeniesEverything(t *testing.T) {
	for _, rs := range [][]Rule{nil, {}} {
		if Evaluate(rs, "usr_maria", "dev_panel_01", "res_diagnostics").Allowed {
			t.Fatal("an empty rule set allowed a request")
		}
	}
}

// TestUnknownEffectDenies checks that a rule this build does not understand
// cannot allow anything.
//
// A future version might add an effect. An older binary reading that rule set
// must deny rather than guess, which is what deny-by-default buys.
func TestUnknownEffectDenies(t *testing.T) {
	rs := rules()
	rs[0].Effect = "permit-everything"
	if Evaluate(rs, "usr_maria", "dev_panel_01", "res_diagnostics").Allowed {
		t.Fatal("a rule with an unrecognised effect allowed a request")
	}
}

// TestOrderDoesNotMatter is the property that justifies having no deny rules.
//
// With allow-only the rule set is a union, so two rules that are each correct
// cannot combine into a wrong answer depending on which is read first.
func TestOrderDoesNotMatter(t *testing.T) {
	a := Rule{PolicyID: "a", Principals: []string{"usr_maria"}, Devices: []string{"dev_1"},
		Resources: []string{"res_1"}, MaxTTL: Duration(5 * time.Minute), Effect: EffectAllow}
	b := Rule{PolicyID: "b", Principals: []string{"usr_maria"}, Devices: []string{"dev_1"},
		Resources: []string{"res_1"}, MaxTTL: Duration(25 * time.Minute), Effect: EffectAllow}

	forward := Evaluate([]Rule{a, b}, "usr_maria", "dev_1", "res_1")
	reverse := Evaluate([]Rule{b, a}, "usr_maria", "dev_1", "res_1")

	if forward.Allowed != reverse.Allowed || forward.MaxTTL != reverse.MaxTTL {
		t.Fatalf("evaluation depends on rule order: %+v vs %+v", forward, reverse)
	}
	// The more permissive of two matching rules wins, so adding a narrow rule
	// cannot silently shorten access a broader one already allowed.
	if forward.MaxTTL != 25*time.Minute {
		t.Fatalf("ttl = %s, want the more permissive 25m", forward.MaxTTL)
	}
}

func TestTTLCappedAtSystemMaximum(t *testing.T) {
	rs := rules()
	rs[0].MaxTTL = Duration(48 * time.Hour)

	d := Evaluate(rs, "usr_maria", "dev_panel_01", "res_diagnostics")
	if !d.Allowed {
		t.Fatal("denied unexpectedly")
	}
	if d.MaxTTL != proto.MaxGrantTTL {
		t.Fatalf("ttl = %s, want the system ceiling %s", d.MaxTTL, proto.MaxGrantTTL)
	}
}

// TestNoWildcards checks that identifiers are matched exactly.
//
// A rule that accepted "*" would change its own blast radius every time a device
// was enrolled, without anyone editing the rule.
func TestNoWildcards(t *testing.T) {
	rs := []Rule{{
		PolicyID: "wild", Principals: []string{"*"}, Devices: []string{"*"},
		Resources: []string{"*"}, MaxTTL: Duration(time.Minute), Effect: EffectAllow,
	}}
	if Evaluate(rs, "usr_maria", "dev_panel_01", "res_diagnostics").Allowed {
		t.Fatal(`"*" was treated as a wildcard rather than as a literal identifier`)
	}
}
