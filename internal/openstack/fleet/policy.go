package fleet

import "time"

// Which commands may be answered from disk, and which may not.
//
// The line is not how old the reading is. It is what the answer is used for.
//
//	listings, pickers, completions   may read the stored reading
//	connecting to a machine          may not
//	changing one                     may not
//	asking a control plane about one may not
//
// A listing is somebody looking. Being a few minutes behind costs them a second
// look, and the age is printed beside it either way. Connecting is somebody
// acting on an address, and an address that stale may belong to a different
// machine on a tenant range that gets reused — so `vctl ssh --vm` reads the
// database every time, and its own staleness check is against the collector's
// pass rather than against anything here. Changing a deployment and then
// diagnosing one have the same shape: both compare what is recorded against
// what is true now, and a stored reading is neither.
//
// This lived in internal/cli as a choice between two duration constants at each
// call site. That put a domain rule in a command file and stated it as a number:
// a caller wrote fleet.FreshFor and the reason it was that one rather than the
// other was in a comment somewhere else. Naming the purposes puts the rule where
// the rest of the fleet's rules are, and makes each call site say what it is
// for rather than how long it will accept.
//
// It does not make the rule enforceable. Nothing stops a connecting path from
// naming a reading purpose, and internal/cli's
// TestNothingThatConnectsOrChangesReadsTheStoredReading is still what holds
// those files away from the stored reading. What this does is make the wrong
// answer harmless where it can: a purpose that may not read returns no reading
// rather than a stale one.
type Purpose int

const (
	// ForListing prints once and exits. There is no second pass to correct it,
	// so it takes the short window — one heartbeat, past which nothing should
	// be presented as current.
	ForListing Purpose = iota

	// ForCompletion is a Tab keypress. It has to answer now or it is not
	// completion, and the cost of being wrong is a name that no longer exists
	// in a list somebody is about to correct by typing.
	ForCompletion

	// ForBrowsing is a screen that re-reads behind itself. It may open on
	// anything still usable because it corrects itself a second later, and the
	// title bar carries the age until it does.
	ForBrowsing

	// ForFallback is the database refusing to answer. Anything still usable
	// beats an error: the reading was passed over a moment ago because
	// something better was expected, and nothing better is.
	//
	// This is most of why anything is stored at all. Without it the fresh
	// window was also the offline window, so a listing went from instant to
	// failed five minutes after the last successful read — during an outage,
	// which is when somebody most wants to see what the fleet looked like.
	ForFallback

	// ForConnecting resolves an address somebody is about to open a session to.
	ForConnecting

	// ForChanging writes to a deployment, having first compared it against what
	// is recorded.
	ForChanging

	// ForDiagnosing asks a farm's own control plane about itself.
	ForDiagnosing

	// numPurposes is the count, and it is what makes the table below testable.
	// Each method is a switch with a default, so a purpose added above and left
	// out of one of them would answer "may not read, zero, unknown" instead of
	// failing — quietly correct-looking for MayReadStored and quietly wrong for
	// anything meant to read. TestEveryPurposeIsInTheTable walks 0..numPurposes
	// so a new constant is covered by having been declared.
	numPurposes
)

// MayReadStored reports whether a stored reading can answer this at all.
func (p Purpose) MayReadStored() bool {
	switch p {
	case ForListing, ForCompletion, ForBrowsing, ForFallback:
		return true
	}
	return false
}

// MaxAge is how old a reading may be and still serve this purpose.
//
// Zero for the purposes that may not read one, so a caller that ignores
// MayReadStored still gets nothing rather than something stale.
func (p Purpose) MaxAge() time.Duration {
	switch p {
	case ForListing:
		return FreshFor
	case ForCompletion, ForBrowsing, ForFallback:
		return UsableFor
	}
	return 0
}

func (p Purpose) String() string {
	switch p {
	case ForListing:
		return "listing"
	case ForCompletion:
		return "completion"
	case ForBrowsing:
		return "browsing"
	case ForFallback:
		return "offline fallback"
	case ForConnecting:
		return "connecting"
	case ForChanging:
		return "changing"
	case ForDiagnosing:
		return "diagnosing"
	}
	return "unknown"
}
