//go:build windows

package winsvc

import "testing"

// TestQuoteArg guards against the unquoted service path problem.
//
// Given C:\Program Files\App\app.exe registered without quotes, the Windows
// loader tries C:\Program.exe first. On a machine where C:\ is writable by a
// non-administrator, that turns an ordinary install into arbitrary code running
// as LocalSystem. It is a long-standing and still commonly found finding, and
// the only defence is quoting the path at registration time.
func TestQuoteArg(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no quoting needed", `C:\svc\agent.exe`, `C:\svc\agent.exe`},
		{"path with a space", `C:\Program Files\App\app.exe`, `"C:\Program Files\App\app.exe"`},
		{"empty argument survives", ``, `""`},
		{"embedded quote is escaped", `a"b`, `"a\"b"`},
		{"trailing backslash before the closing quote", `C:\dir with space\`, `"C:\dir with space\\"`},
		{"plain flag", `-log-level`, `-log-level`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := quoteArg(tc.in); got != tc.want {
				t.Fatalf("quoteArg(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestQuoteAlwaysQuotes checks the executable path is quoted whether or not it
// needs to be.
//
// The install path uses this rather than quoteArg, because "does this contain a
// space" is not a question worth getting subtly wrong when the failure mode is
// arbitrary code running as LocalSystem.
func TestQuoteAlwaysQuotes(t *testing.T) {
	for _, in := range []string{`C:\svcgent.exe`, `C:\Program Files.exe`, `x`} {
		got := quoteAlways(in)
		if got[0] != '"' || got[len(got)-1] != '"' {
			t.Fatalf("quoteAlways(%q) = %q: must always be quoted", in, got)
		}
	}
}

// TestQuoteArgAlwaysQuotesSpaces is the property that actually matters, stated
// separately from the table so it cannot be weakened by editing a case.
func TestQuoteArgAlwaysQuotesSpaces(t *testing.T) {
	paths := []string{
		`C:\Program Files\x\y.exe`,
		`C:\Users\Some User\agent.exe`,
		`C:\a b\c d\e.exe`,
	}
	for _, p := range paths {
		got := quoteArg(p)
		if got[0] != '"' || got[len(got)-1] != '"' {
			t.Fatalf("quoteArg(%q) = %q: a path containing a space must be quoted", p, got)
		}
	}
}
