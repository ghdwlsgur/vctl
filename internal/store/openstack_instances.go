package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Instance is one VM in a deployment.
type Instance struct {
	DeploymentID string `json:"deployment_id"`
	InstanceID   string `json:"instance_id"`
	ProjectID    string `json:"project_id,omitempty"`
	Name         string `json:"name,omitempty"`

	Status     string `json:"status,omitempty"`
	PowerState string `json:"power_state,omitempty"`
	TaskState  string `json:"task_state,omitempty"`

	AvailabilityZone   string `json:"availability_zone,omitempty"`
	HypervisorHostname string `json:"hypervisor_hostname,omitempty"`

	FlavorID string `json:"flavor_id,omitempty"`
	ImageID  string `json:"image_id,omitempty"`

	CreatedAt  *time.Time `json:"created_at,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	ObservedAt time.Time  `json:"observed_at"`

	// MissingSince is set when a collection that reached the deployment did not
	// list this VM. Its age is how a caller tells a deleted machine from one
	// that a single query happened to miss.
	MissingSince *time.Time `json:"missing_since,omitempty"`

	Addresses []InstanceAddress `json:"addresses,omitempty"`
}

// InstanceAddress is one address a VM answers on.
type InstanceAddress struct {
	NetworkName string `json:"network_name,omitempty"`
	Address     string `json:"address"`
	Type        string `json:"type,omitempty"`
	IPVersion   int    `json:"ip_version"`
}

// ReplaceInstances records the VMs a deployment currently has.
//
// Absent VMs are marked, not deleted. A machine missing from one listing may
// have been deleted, or the query may have been scoped wrong, or nova may have
// been mid-restart — and a row that vanishes takes with it the only record that
// the VM ever existed, which is exactly what somebody asks about after an
// incident.
//
// In a transaction because a half-written listing would mark live VMs missing.
func (s *Store) ReplaceInstances(ctx context.Context, deployment string, in []Instance, at time.Time) (seen int, err error) {
	if at.IsZero() {
		at = time.Now()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, i := range in {
		if i.InstanceID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO openstack_instances
				(deployment_id, instance_id, project_id, name, status, power_state, task_state,
				 availability_zone, hypervisor_hostname, flavor_id, image_id,
				 created_at, updated_at, observed_at, missing_since)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14, NULL)
			ON CONFLICT (deployment_id, instance_id) DO UPDATE SET
				project_id=EXCLUDED.project_id, name=EXCLUDED.name,
				status=EXCLUDED.status, power_state=EXCLUDED.power_state,
				task_state=EXCLUDED.task_state,
				availability_zone=EXCLUDED.availability_zone,
				hypervisor_hostname=EXCLUDED.hypervisor_hostname,
				flavor_id=EXCLUDED.flavor_id, image_id=EXCLUDED.image_id,
				created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at,
				observed_at=EXCLUDED.observed_at,
				-- Coming back clears it, so the column always means "missing now".
				missing_since=NULL`,
			deployment, i.InstanceID, i.ProjectID, i.Name, i.Status, i.PowerState, i.TaskState,
			i.AvailabilityZone, i.HypervisorHostname, i.FlavorID, i.ImageID,
			i.CreatedAt, i.UpdatedAt, at); err != nil {
			return 0, err
		}
		// Addresses are replaced wholesale rather than merged: a VM that loses a
		// floating IP has to lose the row, and there is no key to diff on that
		// the address itself does not already provide.
		if _, err := tx.Exec(ctx,
			`DELETE FROM openstack_instance_addresses WHERE deployment_id=$1 AND instance_id=$2`,
			deployment, i.InstanceID); err != nil {
			return 0, err
		}
		for _, a := range i.Addresses {
			if a.Address == "" {
				continue
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO openstack_instance_addresses
					(deployment_id, instance_id, network_name, address, address_type, ip_version)
				VALUES ($1,$2,$3,$4,$5,$6)
				ON CONFLICT (deployment_id, instance_id, address) DO UPDATE SET
					network_name=EXCLUDED.network_name, address_type=EXCLUDED.address_type,
					ip_version=EXCLUDED.ip_version`,
				deployment, i.InstanceID, a.NetworkName, a.Address, a.Type, a.IPVersion); err != nil {
				return 0, err
			}
		}
		seen++
	}

	// Anything this deployment had and did not list now. First absence stamps
	// the time; later ones leave it, so the age is how long it has been gone.
	if _, err := tx.Exec(ctx, `
		UPDATE openstack_instances SET missing_since=$2
		WHERE deployment_id=$1 AND observed_at < $2 AND missing_since IS NULL`,
		deployment, at); err != nil {
		return 0, err
	}
	return seen, tx.Commit(ctx)
}

// InstanceFilter narrows a listing.
type InstanceFilter struct {
	DeploymentID string
	// Hypervisor is nova's name for the host, which is what the instance rows
	// carry — the caller resolves inventory names to it.
	Hypervisor string
	ProjectID  string
	// Address finds the VM answering on an IP, the question asked while
	// somebody is looking at a connection log.
	Address string
	// InstanceID answers the Kubernetes join: a node's spec.providerID is
	// openstack:///<uuid> and carries no deployment.
	InstanceID string
	// IncludeMissing brings back VMs nova no longer lists. Off by default: the
	// common question is what is running now.
	IncludeMissing bool
}

// Instances lists VMs, with their addresses.
func (s *Store) Instances(ctx context.Context, f InstanceFilter) ([]Instance, error) {
	q := `SELECT deployment_id, instance_id, project_id, name, status, power_state, task_state,
		 availability_zone, hypervisor_hostname, flavor_id, image_id,
		 created_at, updated_at, observed_at, missing_since
		FROM openstack_instances WHERE 1=1`
	var args []any
	add := func(clause string, v any) {
		args = append(args, v)
		q += clause + "$" + itoa(len(args))
	}
	if f.DeploymentID != "" {
		add(" AND deployment_id=", f.DeploymentID)
	}
	if f.Hypervisor != "" {
		add(" AND hypervisor_hostname=", f.Hypervisor)
	}
	if f.ProjectID != "" {
		add(" AND project_id=", f.ProjectID)
	}
	if f.InstanceID != "" {
		add(" AND instance_id=", f.InstanceID)
	}
	if f.Address != "" {
		args = append(args, f.Address)
		q += ` AND EXISTS (SELECT 1 FROM openstack_instance_addresses a
			WHERE a.deployment_id = openstack_instances.deployment_id
			  AND a.instance_id = openstack_instances.instance_id
			  AND a.address = $` + itoa(len(args)) + `)`
	}
	if !f.IncludeMissing {
		q += ` AND missing_since IS NULL`
	}
	q += ` ORDER BY deployment_id, name, instance_id`

	rows, err := queryAndCollect(ctx, s.pool, q, args, scanInstance)
	if err != nil {
		return nil, err
	}
	return s.attachAddresses(ctx, rows)
}

func (s *Store) attachAddresses(ctx context.Context, in []Instance) ([]Instance, error) {
	if len(in) == 0 {
		return in, nil
	}
	// One query for the whole listing rather than one per VM: a deployment with
	// a thousand VMs would otherwise be a thousand round trips.
	ids := make([]string, 0, len(in))
	for _, i := range in {
		ids = append(ids, i.InstanceID)
	}
	type addrRow struct {
		InstanceID string
		InstanceAddress
	}
	addrs, err := queryAndCollect(ctx, s.pool, `
		SELECT instance_id, network_name, address, address_type, ip_version
		FROM openstack_instance_addresses WHERE instance_id = ANY($1)
		ORDER BY instance_id, address`, []any{ids},
		func(r pgx.Rows) (addrRow, error) {
			var a addrRow
			err := r.Scan(&a.InstanceID, &a.NetworkName, &a.Address, &a.Type, &a.IPVersion)
			return a, err
		})
	if err != nil {
		return nil, err
	}
	byID := map[string][]InstanceAddress{}
	for _, a := range addrs {
		byID[a.InstanceID] = append(byID[a.InstanceID], a.InstanceAddress)
	}
	for i := range in {
		in[i].Addresses = byID[in[i].InstanceID]
	}
	return in, nil
}

func scanInstance(r pgx.Rows) (Instance, error) {
	var i Instance
	err := r.Scan(&i.DeploymentID, &i.InstanceID, &i.ProjectID, &i.Name,
		&i.Status, &i.PowerState, &i.TaskState,
		&i.AvailabilityZone, &i.HypervisorHostname, &i.FlavorID, &i.ImageID,
		&i.CreatedAt, &i.UpdatedAt, &i.ObservedAt, &i.MissingSince)
	return i, err
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

// HypervisorNames lists the host names nova files VMs under, so a caller can
// map an inventory hostname onto one with the same matcher the reconciler uses.
func (s *Store) HypervisorNames(ctx context.Context, deployment string) ([]string, error) {
	q := `SELECT DISTINCT hypervisor_hostname FROM openstack_instances
		WHERE hypervisor_hostname <> ''`
	var args []any
	if deployment != "" {
		q += ` AND deployment_id=$1`
		args = append(args, deployment)
	}
	return queryAndCollect(ctx, s.pool, q+` ORDER BY 1`, args, scanString)
}
