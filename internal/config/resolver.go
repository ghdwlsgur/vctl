package config

import (
	"context"
	"net"
	"time"
)

// UseDNSServer sends every hostname this process looks up to one nameserver.
//
// It exists because of where the fleet's names live. `vault.sre.local` and
// `vctl-postgres.sre.local` are answered by a DNS server reachable over the
// VPN, and macOS treats anything under `.local` as mDNS first — so each lookup
// waits out a five-second multicast timeout before falling through to the
// server that had the answer all along. Measured on this workstation: 5,009ms
// to resolve, 11ms to connect. Two lookups per command, so ten of a command's
// ten and a half seconds were spent not-finding names.
//
// The whole resolver is replaced rather than each client's dialer. Postgres,
// Vault and SSH then all take the same path without any of them being handed a
// custom dial function — which matters because the one thing that must not
// change here is TLS. `store.Open` pins sslmode=verify-full with no fallbacks,
// and the way that guarantee usually dies is somebody threading a dialer
// through it. Nothing below touches a transport, a certificate or a server
// name; only the answer to "what address is this name".
//
// Unset means unchanged: the operating system resolves as before.
func UseDNSServer(addr string) {
	if addr == "" {
		return
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	net.DefaultResolver = &net.Resolver{
		// The pure-Go resolver, because the cgo one goes back to the system
		// configuration this is meant to step around.
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Short, and deliberately so. A name server that does not answer
			// promptly is the problem being solved, not a reason to wait again.
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
}
