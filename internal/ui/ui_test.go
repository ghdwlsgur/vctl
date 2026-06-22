package ui

import "testing"

func TestTruncate(t *testing.T) {
	const long = "incheon-vm-[surromind]-surromind-k8s-worker-gpu-bw6000"
	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"short unchanged", "sre-srv-0023", 40, "sre-srv-0023"},
		{"exact fit", "abcd", 4, "abcd"},
		{"middle elided", long, 40, "incheon-vm-[surromin…s-worker-gpu-bw6000"},
		{"tiny max", "abcdef", 1, "abcdef"}, // max<=1: unchanged (nothing useful to show)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Truncate(c.in, c.max)
			if got != c.want {
				t.Fatalf("Truncate(%q,%d) = %q, want %q", c.in, c.max, got, c.want)
			}
			// width never exceeds max (except the unchanged-tiny case)
			if c.max > 1 && len([]rune(got)) > c.max {
				t.Fatalf("Truncate(%q,%d) width %d > max", c.in, c.max, len([]rune(got)))
			}
		})
	}
	// head and tail of a long name are both preserved around the ellipsis.
	got := Truncate(long, 40)
	if got[:10] != long[:10] {
		t.Errorf("head not preserved: %q", got)
	}
}
