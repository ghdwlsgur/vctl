package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// A dial error is read for what it says about the far end, and "network is
// unreachable" says nothing about it: that is this machine's routing table,
// and it is what every candidate returns while the VPN is down. Reading it as
// silence reported the whole fleet drifted the moment the tunnel dropped.
func TestClassifyDialSeparatesNoRouteFromSilence(t *testing.T) {
	dial := func(errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: &net.OpError{Op: "connect", Err: errno}}
	}
	for _, tc := range []struct {
		name string
		err  error
		want probeVerdict
	}{
		{"accepted", nil, probeAnswered},
		{"refused: a machine is there", dial(syscall.ECONNREFUSED), probeAnswered},
		{"no route to host: the drift shape on a local subnet", dial(syscall.EHOSTUNREACH), probeSilent},
		{"timeout: nothing answered", &net.OpError{Op: "dial", Err: context.DeadlineExceeded}, probeSilent},
		{"network unreachable: this machine, not the host", dial(syscall.ENETUNREACH), probeNoRoute},
		{"wrapped network unreachable", fmt.Errorf("probe: %w", dial(syscall.ENETUNREACH)), probeNoRoute},
	} {
		if got := classifyDial(tc.err); got != tc.want {
			t.Errorf("%s: classifyDial = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// `vctl ssh` follows JumpVia; a dial from the operator's machine does not. For
// a host behind a jump an unanswered direct dial is what a working setup
// produces, so such hosts are set aside as unprobed rather than dialled and
// called drifted.
func TestProbeCandidatesDoesNotDialHostsBehindAJump(t *testing.T) {
	behind := store.ServerWithStatus{Server: store.Server{
		Hostname: "behind-bastion-01", IP: "192.0.2.10", Port: 22, JumpVia: "bastion-01",
	}}
	p := probeCandidates(context.Background(), []store.ServerWithStatus{behind})
	if len(p.behindJump) != 1 || p.behindJump[0].Hostname != behind.Hostname {
		t.Fatalf("behindJump = %v, want the jump host set aside", hostNames(p.behindJump))
	}
	if len(p.drifted)+len(p.reachable)+len(p.noRoute) != 0 {
		t.Fatalf("a host behind a jump was judged: %+v", p)
	}
}

// The advice to edit the inventory follows only a failure to reach the address.
// A host whose primary is a floating IP reads as drifted by construction — its
// agent never sees that address — so an auth failure there used to end in
// advice to correct a row that was right.
func TestDriftAdviceOnlyFollowsADialFailureOnADirectHost(t *testing.T) {
	direct := &store.Server{Hostname: "gw-01", IP: "192.0.2.240", Port: 22}
	viaJump := &store.Server{Hostname: "inner-01", IP: "192.0.2.50", Port: 22, JumpVia: "gw-01"}
	dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: &net.OpError{Op: "connect", Err: syscall.EHOSTUNREACH}}

	for _, tc := range []struct {
		name string
		sv   *store.Server
		err  error
		want bool
	}{
		{"dial failure, direct host", direct, dialErr, true},
		{"dial failure wrapped by the connector", direct, fmt.Errorf("connect %s: %w", direct.Hostname, dialErr), true},
		{"handshake failure: something answered", direct, errors.New("ssh: handshake failed: certificate rejected"), false},
		{"read failure after connecting", direct, &net.OpError{Op: "read", Err: syscall.ECONNRESET}, false},
		{"dial failure on a host behind a jump: may be the jump", viaJump, dialErr, false},
		{"no error", direct, nil, false},
		{"no server", nil, dialErr, false},
	} {
		if got := driftCouldExplain(tc.sv, tc.err); got != tc.want {
			t.Errorf("%s: driftCouldExplain = %v, want %v", tc.name, got, tc.want)
		}
	}
}
