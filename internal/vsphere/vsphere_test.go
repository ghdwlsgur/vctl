package vsphere

import (
	"context"
	"crypto/tls"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/vmware/govmomi/simulator"
)

// Observe against govmomi's ESXi simulator: one login, one read, and the
// fields the heartbeat and the spec need filled.
func TestObserveSimulatedESXi(t *testing.T) {
	m := simulator.ESX()
	defer m.Remove()
	if err := m.Create(); err != nil {
		t.Fatal(err)
	}
	m.Service.TLS = new(tls.Config) // ESXi only speaks https
	s := m.Service.NewServer()
	defer s.Close()

	pass, _ := s.URL.User.Password()
	tgt := Target{URL: "https://" + s.URL.Host + "/sdk", Username: s.URL.User.Username(), Password: pass, Insecure: true}
	o, err := Observe(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.Product, "ESX") || o.Version == "" {
		t.Errorf("product = %q version %q", o.Product, o.Version)
	}
	if o.CPUCores == 0 || o.CPUPackages == 0 || o.MemoryBytes == 0 {
		t.Errorf("cpu/memory = %d pkgs, %d cores, %d bytes", o.CPUPackages, o.CPUCores, o.MemoryBytes)
	}
	if !o.Active() {
		t.Errorf("connection %q maintenance %v, want active", o.Connection, o.Maintenance)
	}
	sp := o.Spec()
	if sp.OS != o.Product || sp.CPU.Cores != o.CPUCores || sp.Memory.TotalMB != o.MemoryBytes>>20 {
		t.Errorf("spec = %+v", sp)
	}
	if _, ok := o.Details()["product"]; !ok {
		t.Errorf("details = %v", o.Details())
	}
}

func TestObserveWrongPassword(t *testing.T) {
	m := simulator.ESX()
	defer m.Remove()
	if err := m.Create(); err != nil {
		t.Fatal(err)
	}
	m.Service.TLS = new(tls.Config)
	// The simulator checks passwords only when the listener names a user.
	m.Service.Listen = &url.URL{User: url.UserPassword("vctl-ro", "right")}
	s := m.Service.NewServer()
	defer s.Close()
	_, err := Observe(context.Background(), Target{URL: "https://" + s.URL.Host + "/sdk",
		Username: "vctl-ro", Password: "wrong", Insecure: true})
	if err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("err = %v, want a login failure", err)
	}
}

type fakeKV map[string]map[string]string

func (f fakeKV) ReadKV(_ context.Context, path string) (map[string]string, error) {
	if m, ok := f[path]; ok {
		return m, nil
	}
	return nil, errors.New("not found")
}

func TestCredsTarget(t *testing.T) {
	kv := fakeKV{
		"kv/teams/sre/vctl-esxi-sre-srv-0028": {"username": "vctl-ro", "password": "x"},
		"kv/teams/sre/vctl-esxi-sre-srv-0046": {"username": "vctl-ro", "password": "x",
			"url": "https://esxi46.example/sdk", "thumbprint": "aa:bb"},
		"kv/teams/sre/vctl-esxi-sre-srv-0029": {"username": "vctl-ro"},
	}
	c := Creds{KV: kv, Prefix: "kv/teams/sre/"}

	got, err := c.Target(context.Background(), "sre-srv-0028", "192.168.180.81/32", false)
	if err != nil || got.URL != "https://192.168.180.81:443/sdk" {
		t.Fatalf("0028: %+v %v, want the inventory address", got, err)
	}
	got, err = c.Target(context.Background(), "sre-srv-0046", "192.168.173.42", false)
	if err != nil || got.URL != "https://esxi46.example/sdk" || got.Thumbprint != "aa:bb" {
		t.Fatalf("0046: %+v %v, want the secret's url and thumbprint", got, err)
	}
	if _, err := c.Target(context.Background(), "sre-srv-0029", "192.168.180.52", false); err == nil {
		t.Fatal("0029: a secret without a password was accepted")
	}
	if _, err := c.Target(context.Background(), "sre-srv-0099", "10.0.0.1", false); err == nil ||
		!strings.Contains(err.Error(), "vctl-esxi-sre-srv-0099") {
		t.Fatalf("missing secret: err = %v, want the path named", err)
	}
}
