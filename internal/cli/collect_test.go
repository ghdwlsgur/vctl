package cli

import (
	"encoding/json"
	"testing"
)

func TestMapTetra(t *testing.T) {
	exec := tetraEvent{
		NodeName: "h1",
		ProcessExec: &tetraExec{
			Process: tetraProcess{PID: 10, UID: 0, CWD: "/root", Binary: "/usr/bin/id", Arguments: "-u", CgroupID: "12345"},
			Parent:  tetraProcess{PID: 9},
		},
	}
	ev, ok := mapTetra(exec, "", "")
	if !ok {
		t.Fatal("exec should map")
	}
	if ev.Kind != "exec" || ev.Hostname != "h1" || ev.Binary != "/usr/bin/id" ||
		ev.PID != 10 || ev.PPID != 9 || ev.CgroupID != 12345 {
		t.Fatalf("exec mapping wrong: %+v", ev)
	}

	// host override wins over node_name
	if ev, _ := mapTetra(exec, "override", ""); ev.Hostname != "override" {
		t.Fatalf("host override = %q, want override", ev.Hostname)
	}

	exit := tetraEvent{NodeName: "h1", ProcessExit: &tetraExit{Process: tetraProcess{PID: 10, Binary: "/usr/bin/id", CgroupID: "12345"}, Status: 3}}
	ev, ok = mapTetra(exit, "", "")
	if !ok || ev.Kind != "exit" || ev.ExitCode == nil || *ev.ExitCode != 3 || ev.CgroupID != 12345 {
		t.Fatalf("exit mapping wrong: %+v ok=%v", ev, ok)
	}

	// no host and no node_name -> not mappable
	if _, ok := mapTetra(tetraEvent{ProcessExec: &tetraExec{Process: tetraProcess{Binary: "/x"}}}, "", ""); ok {
		t.Fatal("missing host should not map")
	}
	// exec with empty binary -> not mappable
	if _, ok := mapTetra(tetraEvent{NodeName: "h1", ProcessExec: &tetraExec{}}, "", ""); ok {
		t.Fatal("empty binary should not map")
	}
	// neither exec nor exit
	if _, ok := mapTetra(tetraEvent{NodeName: "h1"}, "", ""); ok {
		t.Fatal("empty event should not map")
	}
}

func TestTetraProcessCgroupParse(t *testing.T) {
	// protojson renders uint64 as a string; bad/empty values fall back to 0.
	for in, want := range map[string]int64{"42": 42, "": 0, "notnum": 0} {
		var p tetraProcess
		_ = json.Unmarshal([]byte(`{"cgroup_id":"`+in+`"}`), &p)
		if got := p.cgroup(); got != want {
			t.Errorf("cgroup(%q) = %d, want %d", in, got, want)
		}
	}
}
