package policy

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration marshalling, shared by the types in this package.

func unmarshalDuration(b []byte, out *time.Duration) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30m\": %w", err)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*out = d
	return nil
}

func marshalDuration(d time.Duration) ([]byte, error) {
	return json.Marshal(d.String())
}
