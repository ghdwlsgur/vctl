package hoststatus

import (
	"os"
	"runtime"
	"testing"
)

// The count matches what is actually in the file.
func TestMountCountMatchesTheFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("no /proc/self/mountinfo outside linux")
	}
	got := mountCount()
	if got == nil {
		t.Fatal("no count on a host that has the file")
	}
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want := 0
	for _, c := range b {
		if c == '\n' {
			want++
		}
	}
	if *got != want {
		t.Errorf("count = %d, want %d", *got, want)
	}
}

// Absent is not zero.
//
// A host that measured nothing and a host with an empty mount table are
// different facts, and the alert built on this reads a number. Collapsing the
// two would make every non-linux host look like a host with no mounts.
func TestMountCountIsAbsentRatherThanZeroWhenItCannotMeasure(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this asserts the no-procfs path")
	}
	if got := mountCount(); got != nil {
		t.Errorf("count = %d, want nil where there is no procfs", *got)
	}
}

// Collect carries it through, so the field is populated by the path the agent
// actually uses rather than only by a direct call.
func TestCollectCarriesTheMountCount(t *testing.T) {
	st := Collect("h", "v")
	if runtime.GOOS == "linux" && st.MountCount == nil {
		t.Error("Collect dropped the mount count on linux")
	}
	if runtime.GOOS != "linux" && st.MountCount != nil {
		t.Errorf("Collect invented a mount count: %d", *st.MountCount)
	}
}
