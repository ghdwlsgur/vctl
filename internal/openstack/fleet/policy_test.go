package fleet

import "testing"

// Every purpose answers all three questions.
//
// The methods are switches with a default, so one added to the list above and
// forgotten in a switch does not fail — it falls through to "may not read, zero,
// unknown". For a purpose meant to read, that is the whole policy silently
// turned off for it: every call returns no reading, the command goes to the
// database every time, and nothing says why it got slower.
func TestEveryPurposeIsInTheTable(t *testing.T) {
	for p := range numPurposes {
		if p.String() == "unknown" {
			t.Errorf("purpose %d has no name; it was added without being put in String", int(p))
		}
		if p.MayReadStored() && p.MaxAge() == 0 {
			t.Errorf("%s may read a stored reading but accepts none of any age", p)
		}
		if !p.MayReadStored() && p.MaxAge() != 0 {
			t.Errorf("%s may not read a stored reading but names a window of %s", p, p.MaxAge())
		}
	}
}

// Which side of the line each purpose is on. The table restates the rule rather
// than deriving it, because a test that computed the answer the same way the
// code does would agree with a wrong answer.
func TestWhichPurposesMayBeAnsweredFromDisk(t *testing.T) {
	for _, tc := range []struct {
		why  Purpose
		may  bool
		want string
	}{
		{ForListing, true, "listing"},
		{ForCompletion, true, "completion"},
		{ForBrowsing, true, "browsing"},
		{ForFallback, true, "offline fallback"},
		{ForConnecting, false, "connecting"},
		{ForChanging, false, "changing"},
		{ForDiagnosing, false, "diagnosing"},
	} {
		if got := tc.why.MayReadStored(); got != tc.may {
			t.Errorf("%s may read = %v, want %v", tc.want, got, tc.may)
		}
		if got := tc.why.String(); got != tc.want {
			t.Errorf("purpose %d is called %q, want %q", int(tc.why), got, tc.want)
		}
	}
}

// A listing prints once and exits, so it takes the short window. Everything else
// that reads either corrects itself or is already the fallback.
func TestAPrintedListingTakesTheShortWindow(t *testing.T) {
	if ForListing.MaxAge() != FreshFor {
		t.Errorf("a listing accepts %s, want %s", ForListing.MaxAge(), FreshFor)
	}
	for _, why := range []Purpose{ForCompletion, ForBrowsing, ForFallback} {
		if why.MaxAge() != UsableFor {
			t.Errorf("%s accepts %s, want %s", why, why.MaxAge(), UsableFor)
		}
	}
	// The ordering matters more than either constant: a listing must never
	// accept something a self-correcting screen would not.
	if ForListing.MaxAge() > ForBrowsing.MaxAge() {
		t.Error("a listing accepts an older reading than a screen that re-reads behind itself")
	}
}
