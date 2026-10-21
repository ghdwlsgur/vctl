package vsphere

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	"github.com/vmware/govmomi/simulator"

	"github.com/ghdwlsgur/vctl/internal/store"
	vs "github.com/ghdwlsgur/vctl/internal/vsphere"
)

type fakePollStore struct {
	servers map[string]string // hostname -> ip
	status  []store.ServerStatus
	caps    []store.Capability
	specs   []store.ServerSpec
	errs    []string
}

func (f *fakePollStore) Get(_ context.Context, h string) (*store.Server, error) {
	ip, ok := f.servers[h]
	if !ok {
		return nil, errors.New("no rows in result set")
	}
	return &store.Server{Hostname: h, IP: ip}, nil
}

func (f *fakePollStore) UpsertServerStatus(_ context.Context, st store.ServerStatus) (bool, error) {
	f.status = append(f.status, st)
	return true, nil
}

func (f *fakePollStore) ReplaceCapabilities(_ context.Context, _, _ string, caps []store.Capability) (bool, error) {
	f.caps = append(f.caps, caps...)
	return true, nil
}

func (f *fakePollStore) RecordCapabilityError(_ context.Context, h, kind, msg string) error {
	f.errs = append(f.errs, h+" "+kind+": "+msg)
	return nil
}

func (f *fakePollStore) UpsertServerSpec(_ context.Context, sp store.ServerSpec) (bool, error) {
	f.specs = append(f.specs, sp)
	return true, nil
}

type mapKV map[string]map[string]string

func (m mapKV) ReadKV(_ context.Context, p string) (map[string]string, error) {
	if v, ok := m[p]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}

// One poll against the ESXi simulator writes all three rows the node-agent
// would have, and a host that cannot be reached leaves an error beside its
// last facts instead of a heartbeat.
func TestPollOneWritesHeartbeatCapabilityAndSpec(t *testing.T) {
	m := simulator.ESX()
	defer m.Remove()
	if err := m.Create(); err != nil {
		t.Fatal(err)
	}
	m.Service.TLS = new(tls.Config)
	s := m.Service.NewServer()
	defer s.Close()
	pass, _ := s.URL.User.Password()

	st := &fakePollStore{servers: map[string]string{"sre-srv-0028": "192.0.2.1", "sre-srv-0029": "192.0.2.2"}}
	creds := vs.Creds{Prefix: "kv/teams/sre", KV: mapKV{
		"kv/teams/sre/vctl-esxi-sre-srv-0028": {"username": s.URL.User.Username(), "password": pass,
			"url": "https://" + s.URL.Host + "/sdk"},
		"kv/teams/sre/vctl-esxi-sre-srv-0029": {"username": "u", "password": "p",
			"url": "https://127.0.0.1:1/sdk"},
	}}
	ctx := context.Background()
	if err := pollOne(ctx, st, creds, "sre-srv-0028", pollOptions{insecure: true}); err != nil {
		t.Fatal(err)
	}
	if len(st.status) != 1 || st.status[0].OS != "esxi" || !strings.HasPrefix(st.status[0].AgentVersion, "vsphere-poll/") {
		t.Fatalf("status = %+v", st.status)
	}
	if len(st.caps) != 1 || st.caps[0].Kind != vs.Kind || st.caps[0].Role != vs.Role || !st.caps[0].Active {
		t.Fatalf("caps = %+v", st.caps)
	}
	if len(st.specs) != 1 || st.specs[0].Source != store.SpecSourceVSphere || st.specs[0].Spec.CPU.Cores == 0 {
		t.Fatalf("specs = %+v", st.specs)
	}

	if err := pollOne(ctx, st, creds, "sre-srv-0029", pollOptions{insecure: true}); err == nil {
		t.Fatal("an unreachable host polled fine")
	}
	if len(st.status) != 1 || len(st.errs) != 1 || !strings.HasPrefix(st.errs[0], "sre-srv-0029 vmware:") {
		t.Fatalf("after a failed poll: status=%d errs=%v, want no heartbeat and one recorded error", len(st.status), st.errs)
	}

	// A dry run polls and writes nothing.
	if err := pollOne(ctx, st, creds, "sre-srv-0028", pollOptions{insecure: true, dryRun: true}); err != nil {
		t.Fatal(err)
	}
	if len(st.status) != 1 || len(st.specs) != 1 {
		t.Fatal("dry run wrote")
	}
	if err := pollOne(ctx, st, creds, "sre-srv-9999", pollOptions{}); err == nil || !strings.Contains(err.Error(), "inventory") {
		t.Fatalf("unknown host: %v", err)
	}
}
