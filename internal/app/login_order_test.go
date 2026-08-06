package app

import (
	"testing"

	"github.com/ghdwlsgur/vctl/internal/config"
)

// Naming an auth method is a statement about which identity this installation
// should have, and AppRole going first ignored it.
//
// Measured on a real workstation: `auth_method: userpass` in the config, an
// AppRole role-id beside it, and every lapsed token silently replaced by the
// AppRole's. vctl ran as vctl-user — a role that reads the inventory and little
// else — so `vctl openstack list` worked while `vctl ssh`, `vctl edit` and
// `vctl openstack reconcile` returned 403 on paths the operator's own identity
// holds. Nothing said which identity was in use, which is why it took a Vault
// policy read to find.
func TestAConfiguredMethodOutranksAppRoleWhenSomebodyCanAnswer(t *testing.T) {
	for _, tc := range []struct {
		name        string
		method      string
		interactive bool
		want        bool
	}{
		{"userpass at a terminal", "userpass", true, true},
		{"oidc at a terminal", "oidc", true, true},

		// No terminal, nobody to prompt: every pod, timer and CI job. AppRole
		// has to keep going first or unattended vctl stops working.
		{"userpass with no terminal", "userpass", false, false},
		{"oidc with no terminal", "oidc", false, false},

		// These name the unattended paths themselves, so preferring them here
		// would be the same order by a longer route.
		{"approle", "approle", true, false},
		{"kubernetes", "kubernetes", true, false},

		// No preference expressed.
		{"unset", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &App{
				Cfg:         &config.Config{AuthMethod: tc.method},
				Interactive: func() bool { return tc.interactive },
			}
			if got := a.preferConfiguredLogin(); got != tc.want {
				t.Errorf("preferConfiguredLogin() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Case is not part of the statement. A config saying "UserPass" means the same
// thing, and treating it as an unknown method would put the operator back on
// the AppRole without a word.
func TestTheConfiguredMethodIsReadCaseInsensitively(t *testing.T) {
	a := &App{
		Cfg:         &config.Config{AuthMethod: "UserPass"},
		Interactive: func() bool { return true },
	}
	if !a.preferConfiguredLogin() {
		t.Error("a method named in mixed case was not recognised")
	}
}

// The order is the behaviour, so it is asserted directly.
//
// Testing only the predicate left the wiring uncovered: the branch could be
// deleted from EnsureLogin entirely and every test still passed.
func TestLoginOrderPutsTheOperatorsIdentityFirstOnlyAtATerminal(t *testing.T) {
	at := func(method string, interactive bool) []string {
		return (&App{
			Cfg:         &config.Config{AuthMethod: method},
			Interactive: func() bool { return interactive },
		}).loginOrder()
	}

	// Somebody is there and said which identity they want.
	if got := at("userpass", true); len(got) != 1 || got[0] != loginConfigured {
		t.Errorf("order = %v, want the configured method alone", got)
	}
	// Nobody to ask: every pod, timer and CI job. AppRole must stay first or
	// unattended vctl stops working.
	got := at("userpass", false)
	if len(got) == 0 || got[0] != loginAppRole {
		t.Fatalf("order = %v, want AppRole first with no terminal", got)
	}
	if got[len(got)-1] != loginConfigured {
		t.Errorf("order = %v, want the configured method as the last resort", got)
	}
	// Kubernetes behind AppRole, unchanged.
	var iAppRole, iK8s = -1, -1
	for i, m := range got {
		switch m {
		case loginAppRole:
			iAppRole = i
		case loginKubernetes:
			iK8s = i
		}
	}
	if iK8s < iAppRole {
		t.Errorf("order = %v, want kubernetes after approle", got)
	}
}
