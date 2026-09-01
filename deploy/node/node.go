// Package node exposes the node-agent's deploy artifacts to Go code.
//
// The systemd unit below is the same file the ansible role ships
// (roles/vctl_host copies it from this directory), and `vctl install` writes
// it over SSH. Embedding here — where the file lives — keeps one source for
// both paths; a string constant in internal/cli held a second copy pinned by
// a test, which detected drift after the fact instead of making it impossible.
package node

import _ "embed"

// AgentUnit is deploy/node/vctl-node-agent.service, byte for byte.
//
//go:embed vctl-node-agent.service
var AgentUnit string
