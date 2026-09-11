package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// K8sCluster is one Kubernetes cluster vctl can hand out access to: where it
// is and how a token for it is obtained. No credential is ever in this row —
// see internal/cli/k8s.go.
type K8sCluster struct {
	Name          string
	Site          string
	APIServer     string // https://host:port
	TLSServerName string
	CAPEM         string
	Reach         string // "tunnel" | "direct"
	TokenSource   string // "vault:<mount>" | "kv:<path>"
	Note          string
	UpdatedAt     time.Time
	UpdatedBy     string
}

// TokenSourceKind splits token_source into its scheme and the rest:
// ("vault", "kubernetes/core-sre") or ("kv", "kv/teams/sre/k8s/x").
func (c K8sCluster) TokenSourceKind() (kind, ref string) {
	kind, ref, _ = strings.Cut(c.TokenSource, ":")
	return kind, ref
}

// ErrK8sClusterNotFound is a name the inventory does not have.
var ErrK8sClusterNotFound = errors.New("no such cluster")

// ValidateK8sCluster is the shape check the database also enforces, run first
// so the operator gets a sentence rather than a constraint name.
func ValidateK8sCluster(c K8sCluster) error {
	switch {
	case strings.TrimSpace(c.Name) == "":
		return errors.New("a cluster needs a name")
	case !strings.HasPrefix(c.APIServer, "https://"):
		return fmt.Errorf("api server %q must be an https:// URL", c.APIServer)
	case c.Reach != "tunnel" && c.Reach != "direct":
		return fmt.Errorf("reach must be tunnel or direct, not %q", c.Reach)
	}
	kind, ref := c.TokenSourceKind()
	if (kind != "vault" && kind != "kv") || ref == "" {
		return fmt.Errorf("token source must be vault:<mount> or kv:<path>, not %q", c.TokenSource)
	}
	return nil
}

const k8sClusterCols = `name, site, api_server, tls_server_name, ca_pem, reach, token_source, note, updated_at, updated_by`

func scanK8sCluster(r pgx.Rows) (K8sCluster, error) {
	var c K8sCluster
	err := r.Scan(&c.Name, &c.Site, &c.APIServer, &c.TLSServerName, &c.CAPEM, &c.Reach, &c.TokenSource, &c.Note, &c.UpdatedAt, &c.UpdatedBy)
	return c, err
}

// K8sClusters lists every cluster, grouped by site then name.
func (s *Store) K8sClusters(ctx context.Context) ([]K8sCluster, error) {
	return queryAndCollect(ctx, s.pool, `SELECT `+k8sClusterCols+` FROM k8s_clusters ORDER BY site, name`, nil, scanK8sCluster)
}

// K8sCluster reads one cluster by name.
func (s *Store) K8sCluster(ctx context.Context, name string) (K8sCluster, error) {
	out, err := queryAndCollect(ctx, s.pool, `SELECT `+k8sClusterCols+` FROM k8s_clusters WHERE name = $1`, []any{name}, scanK8sCluster)
	if err != nil {
		return K8sCluster{}, err
	}
	if len(out) == 0 {
		return K8sCluster{}, fmt.Errorf("%s: %w", name, ErrK8sClusterNotFound)
	}
	return out[0], nil
}

// K8sClusterUpsert declares or updates a cluster.
func (s *Store) K8sClusterUpsert(ctx context.Context, c K8sCluster) error {
	if err := ValidateK8sCluster(c); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO k8s_clusters (name, site, api_server, tls_server_name, ca_pem, reach, token_source, note, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9)
		ON CONFLICT (name) DO UPDATE SET
			site = EXCLUDED.site, api_server = EXCLUDED.api_server,
			tls_server_name = EXCLUDED.tls_server_name, ca_pem = EXCLUDED.ca_pem,
			reach = EXCLUDED.reach, token_source = EXCLUDED.token_source,
			note = EXCLUDED.note, updated_at = now(), updated_by = EXCLUDED.updated_by`,
		c.Name, c.Site, c.APIServer, c.TLSServerName, c.CAPEM, c.Reach, c.TokenSource, c.Note, c.UpdatedBy)
	return err
}

// K8sClusterDelete removes a cluster; a name that was not there is an error,
// so a typo does not report success.
func (s *Store) K8sClusterDelete(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM k8s_clusters WHERE name = $1`, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s: %w", name, ErrK8sClusterNotFound)
	}
	return nil
}
