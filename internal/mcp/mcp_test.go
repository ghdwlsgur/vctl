package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The protocol layer never needed Vault or Postgres, but living inside the
// CLI package it was only reachable through them. These are the rules the
// transport promises whatever the tools do.

func req(id, method, params string) *request {
	r := &request{JSONRPC: "2.0", Method: method}
	if id != "" {
		r.ID = json.RawMessage(id)
	}
	if params != "" {
		r.Params = json.RawMessage(params)
	}
	return r
}

func TestInitializeAnswersWithTheSuppliedVersion(t *testing.T) {
	s := &server{deps: Deps{Version: "v9.9.9"}}
	resp, respond := s.dispatch(context.Background(), req("1", "initialize", ""))
	if !respond || resp.Error != nil {
		t.Fatalf("initialize = %+v (respond=%v)", resp, respond)
	}
	info := resp.Result.(map[string]any)["serverInfo"].(map[string]any)
	if info["version"] != "v9.9.9" {
		t.Fatalf("serverInfo = %+v, want the injected version", info)
	}
}

// A notification has no id, so there is nothing to address a reply to — and
// answering one anyway would interleave an unaddressed frame into the stream.
func TestNotificationsGetNoReply(t *testing.T) {
	s := &server{}
	for _, method := range []string{"notifications/initialized", "tools/call", "no-such-method"} {
		if _, respond := s.dispatch(context.Background(), req("", method, "")); respond {
			t.Errorf("notification %q was answered", method)
		}
	}
}

func TestUnknownMethodIsAJSONRPCError(t *testing.T) {
	s := &server{}
	resp, respond := s.dispatch(context.Background(), req("7", "tools/uninstall", ""))
	if !respond || resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("unknown method = %+v", resp)
	}
}

// A tool error is reported in-band as isError content, not as a protocol
// error: the agent should read it, not the transport.
func TestUnknownToolIsReportedInBand(t *testing.T) {
	s := &server{}
	out := s.callTool(context.Background(), json.RawMessage(`{"name":"vctl_rm_rf"}`))
	if out["isError"] != true {
		t.Fatalf("unknown tool = %+v, want isError", out)
	}
	text := out["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, "vctl_rm_rf") {
		t.Fatalf("error text %q does not name the tool", text)
	}
}

// Every advertised tool must dispatch somewhere; a catalog entry with no
// handler is a promise the server cannot keep.
func TestEveryAdvertisedToolDispatches(t *testing.T) {
	s := &server{deps: Deps{NewApp: nil}}
	for _, tl := range tools() {
		func() {
			defer func() {
				// Reaching the nil NewApp means the dispatch found a handler;
				// only "unknown tool" returns before touching dependencies.
				_ = recover()
			}()
			if _, err := s.runTool(context.Background(), tl.Name, map[string]any{
				"query": "q", "host": "h", "command": "c",
			}); err != nil && strings.Contains(err.Error(), "unknown tool") {
				t.Errorf("advertised tool %q has no handler", tl.Name)
			}
		}()
	}
}
