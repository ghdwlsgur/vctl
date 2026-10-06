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

// SessionAgentUnit is the outbound node-access renewal service definition.
//
//go:embed vctl-session-agent.service
var SessionAgentUnit string

// VMSessionAgentUnit permits privileged interactive guest sessions while
// retaining bounded CPU, memory, and process use. It is separate from the
// deliberately restrictive host status-agent unit.
//
//go:embed vctl-vm-session-agent.service
var VMSessionAgentUnit string
