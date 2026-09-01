package cli

import (
	"fmt"
	"strings"
	"unicode"
)

// validLoginUser rejects a login name that something downstream could read as
// anything other than a login name.
//
// The inventory's ssh_user reaches two very different consumers. `vctl ssh`
// hands it to the in-process SSH client as a principal, where a strange value
// is merely a failed login. `vctl trust-ca` hands it to an external `ssh`
// binary as part of `user@host`, where a value starting with `-` is parsed as
// an option — `-oProxyCommand=…` runs a command on the operator's workstation.
// The argv is built with a `--` separator as well; this check is the other
// half, so a value that could never be a user name is refused where the
// operator can still see why.
func validLoginUser(u string) error {
	if u == "" {
		return fmt.Errorf("login user is empty")
	}
	if strings.HasPrefix(u, "-") {
		return fmt.Errorf("login user %q must not start with '-'", u)
	}
	for _, r := range u {
		switch {
		case unicode.IsSpace(r), unicode.IsControl(r):
			return fmt.Errorf("login user %q contains whitespace or control characters", u)
		case r == '@', r == ':', r == '/':
			return fmt.Errorf("login user %q contains %q, which is not part of a user name", u, r)
		}
	}
	return nil
}
