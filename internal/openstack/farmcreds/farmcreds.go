// Package farmcreds reads a deployment's OpenStack admin credentials from
// Vault, at use time.
//
// Read at use time and never written anywhere: the whole reason reconciling
// runs centrally rather than on each host is that a status agent should not
// be able to read an OpenStack admin credential, and putting one in a file
// would give that back.
//
// The schema — which KV keys hold what, how a farm's id becomes a secret
// path — is a fact about the fleet, not about any one command. It lived in
// the CLI's reconcile adapter file with two consumers already (reconcile and
// farm doctor), which is one consumer past where a copy starts to drift. The
// path prefix is configuration (vault_farm_prefix): it names a team's KV
// mount, which is organization surface, not code.
package farmcreds

import (
	"context"
	"fmt"
	"strings"

	"github.com/ghdwlsgur/vctl/internal/openstackapi"
)

// KV reads one Vault KV secret. Satisfied by *vaultc.Client.
type KV interface {
	ReadKV(ctx context.Context, path string) (map[string]string, error)
}

// Store reads farm credentials.
type Store struct {
	KV KV
	// Prefix is the KV path the farm secrets live under, from config
	// vault_farm_prefix.
	Prefix string
}

// Key turns a deployment id into the secret's path segment.
//
// A colon in a Vault path is legal but awkward everywhere it is then typed.
// The port still has to survive: two deployments can share an address.
func Key(id string) string {
	return "vctl-" + strings.ReplaceAll(id, ":", "_")
}

// ForFarm reads one deployment's admin credentials.
func (s Store) ForFarm(ctx context.Context, id string) (openstackapi.Credentials, error) {
	path := s.Prefix + "/" + Key(id)
	secret, err := s.KV.ReadKV(ctx, path)
	if err != nil {
		return openstackapi.Credentials{}, fmt.Errorf("no credentials at %s (%w)", path, err)
	}
	c := openstackapi.Credentials{
		AuthURL:     secret["auth_url"],
		Username:    secret["username"],
		Password:    secret["password"],
		ProjectName: secret["project_name"],
		UserDomain:  secret["user_domain"],
		ProjectDom:  secret["project_domain"],
	}
	if c.AuthURL == "" {
		// The deployment id is the endpoint's host; the scheme is not part of
		// it, so a stored auth_url is what says which one to use.
		return c, fmt.Errorf("credentials at %s carry no auth_url", path)
	}
	return c, nil
}
