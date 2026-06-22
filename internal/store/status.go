package store

import (
	"context"
	"database/sql"
	"time"
)

// ServerStatus is runtime state reported by vctl node-agent. It is observation,
// not inventory authority.
type ServerStatus struct {
	Hostname         string
	LastSeenAt       time.Time
	AgentVersion     string
	OS               string
	Kernel           string
	UptimeSeconds    int64
	Load1            *float64
	MemoryUsedPct    *float64
	DiskRootUsedPct  *float64
	SSHDOK           *bool
	KubeletOK        *bool
	CRIOOK           *bool
	DockerOK         *bool
	AuditCollectorOK *bool
}

// ServerWithStatus combines operator-managed inventory with observed runtime state.
type ServerWithStatus struct {
	Server
	Status *ServerStatus
}

// UpsertServerStatus records one heartbeat. It intentionally refuses to create
// inventory: if hostname is absent from servers, zero rows are affected.
func (s *Store) UpsertServerStatus(ctx context.Context, st ServerStatus) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO server_status
			(hostname, last_seen_at, agent_version, os, kernel, uptime_seconds, load1,
			 memory_used_pct, disk_root_used_pct, sshd_ok, kubelet_ok, crio_ok, docker_ok, audit_collector_ok, updated_at)
		SELECT $1, now(), NULLIF($2,''), NULLIF($3,''), NULLIF($4,''), NULLIF($5::bigint,0), $6,
		       $7, $8, $9, $10, $11, $12, $13, now()
		WHERE EXISTS (SELECT 1 FROM servers WHERE hostname=$1)
		ON CONFLICT (hostname) DO UPDATE SET
			last_seen_at=EXCLUDED.last_seen_at,
			agent_version=EXCLUDED.agent_version,
			os=EXCLUDED.os,
			kernel=EXCLUDED.kernel,
			uptime_seconds=EXCLUDED.uptime_seconds,
			load1=EXCLUDED.load1,
			memory_used_pct=EXCLUDED.memory_used_pct,
			disk_root_used_pct=EXCLUDED.disk_root_used_pct,
			sshd_ok=EXCLUDED.sshd_ok,
			kubelet_ok=EXCLUDED.kubelet_ok,
			crio_ok=EXCLUDED.crio_ok,
			docker_ok=EXCLUDED.docker_ok,
			audit_collector_ok=EXCLUDED.audit_collector_ok,
			updated_at=now()`,
		st.Hostname, st.AgentVersion, st.OS, st.Kernel, st.UptimeSeconds, st.Load1,
		st.MemoryUsedPct, st.DiskRootUsedPct, st.SSHDOK, st.KubeletOK, st.CRIOOK, st.DockerOK, st.AuditCollectorOK)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ListWithStatus returns inventory rows with optional runtime status.
func (s *Store) ListWithStatus(ctx context.Context, dc string) ([]ServerWithStatus, error) {
	q := `SELECT ` + prefixedSelectCols("srv") + `,
		       coalesce(ss.hostname,''), ss.last_seen_at, coalesce(ss.agent_version,''), coalesce(ss.os,''), coalesce(ss.kernel,''),
		       coalesce(ss.uptime_seconds,0), ss.load1, ss.memory_used_pct, ss.disk_root_used_pct,
		       ss.sshd_ok, ss.kubelet_ok, ss.crio_ok, ss.docker_ok, ss.audit_collector_ok
		FROM servers srv
		LEFT JOIN server_status ss ON ss.hostname = srv.hostname`
	var args []any
	if dc != "" {
		q += ` WHERE srv.dc=$1`
		args = append(args, dc)
	}
	q += ` ORDER BY srv.dc, srv.hostname`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ServerWithStatus
	for rows.Next() {
		var item ServerWithStatus
		var statusHost string
		var st ServerStatus
		var lastSeen sql.NullTime
		var load1, memoryUsed, diskUsed sql.NullFloat64
		var sshdOK, kubeletOK, crioOK, dockerOK, auditCollectorOK sql.NullBool
		err := rows.Scan(&item.Hostname, &item.IP, &item.Port, &item.User, &item.JumpVia, &item.DC, &item.CARole,
			&item.CAKeyVersion, &item.LastSeenUp, &statusHost, &lastSeen, &st.AgentVersion, &st.OS, &st.Kernel,
			&st.UptimeSeconds, &load1, &memoryUsed, &diskUsed, &sshdOK, &kubeletOK, &crioOK, &dockerOK, &auditCollectorOK)
		if err != nil {
			return nil, err
		}
		if statusHost != "" {
			st.Hostname = statusHost
			if lastSeen.Valid {
				st.LastSeenAt = lastSeen.Time
			}
			st.Load1 = nullFloatPtr(load1)
			st.MemoryUsedPct = nullFloatPtr(memoryUsed)
			st.DiskRootUsedPct = nullFloatPtr(diskUsed)
			st.SSHDOK = nullBoolPtr(sshdOK)
			st.KubeletOK = nullBoolPtr(kubeletOK)
			st.CRIOOK = nullBoolPtr(crioOK)
			st.DockerOK = nullBoolPtr(dockerOK)
			st.AuditCollectorOK = nullBoolPtr(auditCollectorOK)
			item.Status = &st
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func nullFloatPtr(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	return &v.Float64
}

func nullBoolPtr(v sql.NullBool) *bool {
	if !v.Valid {
		return nil
	}
	return &v.Bool
}

func prefixedSelectCols(alias string) string {
	p := alias + "."
	return p + "hostname, host(" + p + "ip), " + p + "ssh_port, " + p + "ssh_user, coalesce(" + p + "jump_via,''), " +
		p + "dc, " + p + "ca_role, " + p + "ca_key_version, " + p + "last_seen_up"
}
