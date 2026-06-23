package hoststatus

import (
	"strings"
	"testing"
)

func TestParseMemUsedPct(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want *float64
	}{
		{
			name: "computes used percentage",
			in:   "MemTotal:        100 kB\nMemAvailable:     25 kB\n",
			want: ptr(75.0),
		},
		{
			name: "missing fields returns nil",
			in:   "Buffers:        1234 kB\nCached:         5678 kB\n",
			want: nil,
		},
		{
			name: "total not positive returns nil",
			in:   "MemTotal:        0 kB\nMemAvailable:     25 kB\n",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMemUsedPct(strings.NewReader(tt.in))
			assertFloatPtr(t, got, tt.want)
		})
	}
}

func TestParseLoad1(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want *float64
	}{
		{name: "valid", in: "0.42 0.51 0.60 1/234 5678", want: ptr(0.42)},
		{name: "empty", in: "", want: nil},
		{name: "garbage", in: "notanumber 0.5", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLoad1(tt.in)
			assertFloatPtr(t, got, tt.want)
		})
	}
}

func TestParseUptimeSeconds(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int64
	}{
		{name: "valid", in: "12345.67 9876.54", want: 12345},
		{name: "empty", in: "", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseUptimeSeconds(tt.in); got != tt.want {
				t.Errorf("parseUptimeSeconds(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func ptr(f float64) *float64 { return &f }

func assertFloatPtr(t *testing.T, got, want *float64) {
	t.Helper()
	switch {
	case got == nil && want == nil:
		return
	case got == nil || want == nil:
		t.Fatalf("got %v, want %v", fmtPtr(got), fmtPtr(want))
	case *got != *want:
		t.Fatalf("got %v, want %v", *got, *want)
	}
}

func fmtPtr(p *float64) interface{} {
	if p == nil {
		return nil
	}
	return *p
}
