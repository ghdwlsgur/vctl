package nodeaccess

import (
	"crypto/x509"
	"net/url"
	"testing"
	"time"
)

func TestRequestValidateAllowsTypedOperationsAndRejectsShellInput(t *testing.T) {
	now := time.Now()
	valid := Request{
		Version:   ProtocolVersion,
		ID:        "request-123456",
		Operation: OperationServiceJournal,
		Params:    map[string]string{"service": "nova-api.service", "lines": "100"},
		Deadline:  now.Add(time.Minute),
	}
	if err := valid.Validate(now); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Request)
	}{
		{"shell operation", func(r *Request) { r.Operation = Operation("shell") }},
		{"arbitrary command parameter", func(r *Request) { r.Params["command"] = "id; cat /etc/shadow" }},
		{"option-like service", func(r *Request) { r.Params["service"] = "--help" }},
		{"too many journal lines", func(r *Request) { r.Params["lines"] = "501" }},
		{"expired request", func(r *Request) { r.Deadline = now }},
		{"excessive request lifetime", func(r *Request) { r.Deadline = now.Add(3 * time.Minute) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := valid
			request.Params = map[string]string{"service": "nova-api.service", "lines": "100"}
			tc.mutate(&request)
			if err := request.Validate(now); err == nil {
				t.Fatal("invalid request was accepted")
			}
		})
	}
}

func TestNodeURIAndIdentity(t *testing.T) {
	uri, err := NodeURI("farm-controller-01")
	if err != nil {
		t.Fatal(err)
	}
	if want := "spiffe://vctl.local/node/farm-controller-01"; uri != want {
		t.Fatalf("NodeURI() = %q, want %q", uri, want)
	}
	for _, invalid := range []string{"", "../controller", "controller?x=1", "controller/name", "-controller"} {
		if _, err := NodeURI(invalid); err == nil {
			t.Errorf("NodeURI(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestVMURIAndIdentity(t *testing.T) {
	const instanceUUID = "01234567-89ab-cdef-0123-456789abcdef"
	uri, err := VMURI(instanceUUID)
	if err != nil {
		t.Fatal(err)
	}
	if want := "spiffe://vctl.local/vm/" + instanceUUID; uri != want {
		t.Fatalf("VMURI() = %q, want %q", uri, want)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NodeIdentity(&x509.Certificate{URIs: []*url.URL{parsed}})
	if err != nil {
		t.Fatal(err)
	}
	if got != instanceUUID {
		t.Fatalf("NodeIdentity() = %q, want %q", got, instanceUUID)
	}
	for _, invalid := range []string{"", "0123456789abcdef", "01234567-89AB-CDEF-0123-456789ABCDEF"} {
		if _, err := VMURI(invalid); err == nil {
			t.Errorf("VMURI(%q) unexpectedly succeeded", invalid)
		}
	}
}
