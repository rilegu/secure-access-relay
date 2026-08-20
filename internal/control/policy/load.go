package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// LoadRules reads a policy file.
//
// A missing file is **not** an empty rule set by accident — it is reported, and
// the caller decides. Silently treating "no policy file" as "no rules" would be
// safe here only because the default is denial; making it explicit means an
// operator who deleted the file by mistake finds out, rather than discovering it
// when every request starts being refused.
func LoadRules(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}

	var rules []Rule
	dec := json.NewDecoder(bytes.NewReader(b))
	// A misspelled field silently dropped would be a restriction the operator
	// believes is in force and is not.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rules); err != nil {
		return nil, fmt.Errorf("parse policy in %s: %w", path, err)
	}

	for i, r := range rules {
		if r.PolicyID == "" {
			return nil, fmt.Errorf("policy %d has no policy_id; an allow that cannot be named cannot be audited", i)
		}
		if r.Effect != EffectAllow {
			return nil, fmt.Errorf("policy %q has effect %q; only %q is supported", r.PolicyID, r.Effect, EffectAllow)
		}
		if len(r.Principals) == 0 || len(r.Devices) == 0 || len(r.Resources) == 0 {
			// A rule with an empty list matches nothing, which is harmless but
			// almost certainly not what was meant. Refusing it surfaces the
			// mistake at load rather than as an unexplained denial later.
			return nil, fmt.Errorf("policy %q has an empty principals, devices, or resources list", r.PolicyID)
		}
	}
	return rules, nil
}
