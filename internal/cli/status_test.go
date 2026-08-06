package cli

import "testing"

// The warning has to fire on a machine identity and stay quiet on a person.
//
// The first version compared the token's method against the configured one, and
// that is the wrong question: `vctl login` uses OIDC on this fleet even where
// the config says userpass, so a perfectly good session was reported as broken
// — with the claim "ssh, edit and reconcile will not work" printed directly
// above a line reporting the SSH CA read had succeeded.
//
// What separates the two is the entity, not the method. Measured: the AppRole
// token and the person's token carried the *same* token policy
// (`default, vctl-user`); only the person's carried identity policies from
// group membership.
func TestMachineIdentityIsWhatDistinguishesTheTwo(t *testing.T) {
	for _, tc := range []struct {
		method string
		want   bool
	}{
		{"approle", true},
		{"kubernetes", true},
		{"AppRole", true}, // case is not part of the statement
		{"oidc", false},   // what `vctl login` actually produces
		{"userpass", false},
		{"", false},
	} {
		if got := machineIdentity(tc.method); got != tc.want {
			t.Errorf("machineIdentity(%q) = %v, want %v", tc.method, got, tc.want)
		}
	}
}
