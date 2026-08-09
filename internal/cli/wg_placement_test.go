package cli

import (
	"strings"
	"testing"
)

// Placement: what owns an endpoint on screen, and who is allowed to draw it.
//
// Four lanes place endpoints — the mesh stack, the hub-zone chip row, the
// far-zone rows and the hop chips. Each used to carry its own copy of "does this
// node have a physical host, and what does that host look like". Three wrote
// their own rectangle; the fourth wrote nothing, so the same VM showed its
// compute host or not depending on which lane a filter put it in. Nothing caught
// it: the model returned the right answer either way, and the bug was entirely
// in what was left on the screen.
//
// These pin the two halves of the fix. The arithmetic below says the frame is
// one rule; the source guard says no lane may go around it.

// The numbers are not arbitrary — they are what the chip and hop lanes already
// drew before the rule was shared. Pinning them here is what makes the
// extraction a refactor rather than a redesign nobody measured.
func TestPlacementFrameIsTheSameArithmeticInEveryLane(t *testing.T) {
	got := runModelJS(t, `
console.log(JSON.stringify([
  hostFrame({x:100,y:200,w:220,h:50}),   // hub-zone chip: a 50-high card
  hostFrame({x:64,y:300,w:200,h:52}),    // hop chip: a 52-high card
]));
`)
	// pad 10 on three sides, cap 26 at the top for the host's name:
	// a 50-high card sits in an 86-high frame, a 52 in an 88.
	want := `[{"x":90,"y":174,"width":240,"height":86,"rx":10},` +
		`{"x":54,"y":274,"width":220,"height":88,"rx":10}]`
	if got != want {
		t.Errorf("host frame = %s, want %s", got, want)
	}
}

// The far-zone lane frames a whole cluster rather than one card, so it hands
// over the cluster's interior and expects the frame back at the cluster's own
// outline. If that round trip ever stops landing on the number the lane laid out
// with, the host boxes drift out of their zones by a few pixels a release.
func TestPlacementFrameRoundTripsAClusterOutline(t *testing.T) {
	got := runModelJS(t, `
const EPX=760, EPW=300, ry=140, clusterH=180;
const f = hostFrame({x:EPX, y:ry+HOSTFRAME.cap, w:EPW, h:clusterH-HOSTFRAME.cap-HOSTFRAME.pad});
console.log(JSON.stringify([f.x===EPX-10, f.y===ry, f.width===EPW+20, f.height===clusterH]));
`)
	if want := `[true,true,true,true]`; got != want {
		t.Errorf("cluster round trip = %s, want %s", got, want)
	}
}

// A placement with no host has to be usable, not merely falsy: the hop lane
// sizes its card with Math.max(..., captionWidth), and an undefined there makes
// the whole width NaN and the chip vanish.
func TestPlacementWithoutAHostStillMeasures(t *testing.T) {
	got := runModelJS(t, `
const N=new Map([["vm-1",{id:"vm-1",label:"vm-1"}],["h-1",{id:"h-1",label:"sre-srv-0031",ip:"10.0.0.31"}]]);
const bare = place(N, N.get("vm-1"));
const owned = place(N, {id:"vm-2",label:"vm-2",parent:"h-1"});
console.log(JSON.stringify([
  bare.host, bare.caption, bare.captionWidth,
  owned.host.label, owned.caption,
  Math.max(200, owned.captionWidth) > 200,
]));
`)
	want := `[null,"",0,"sre-srv-0031","PHYSICAL HOST · sre-srv-0031 · 10.0.0.31",true]`
	if got != want {
		t.Errorf("placement = %s, want %s", got, want)
	}
}

// A host the inventory has no address for is named without a dangling separator.
func TestPlacementCaptionOmitsAMissingAddress(t *testing.T) {
	got := runModelJS(t, `console.log(hostCaption({label:"sre-srv-0031"}));`)
	if want := "PHYSICAL HOST · sre-srv-0031"; got != want {
		t.Errorf("caption = %q, want %q", got, want)
	}
}

// The guard that makes the extraction hold.
//
// A lane that draws its own host rectangle is a lane that can forget to, and
// that is exactly how the physical host went missing from the hop chips. There
// is one place in the view that paints a host frame and one that paints its
// name; a fifth renderer — for a role, an OpenStack farm, a Kubernetes cluster —
// has to go through them or fail here.
func TestPlacementOnlyTheSharedGlyphDrawsAPhysicalHost(t *testing.T) {
	if n := strings.Count(wgViewJS, `"hbox k-host"`); n != 1 {
		t.Errorf(`wg_view.js paints the physical-host frame %d times, want 1 (drawHostFrame).
A lane drawing its own frame is a lane that can forget to — see the hop chips.`, n)
	}
	// drawHostFrame's cap and drawHostCaption's line, and nothing else.
	if n := strings.Count(wgViewJS, `class: "htit"`); n != 2 {
		t.Errorf(`wg_view.js writes a physical-host name %d times, want 2 (drawHostFrame, drawHostCaption).`, n)
	}
	for _, fn := range []string{"function drawHostFrame(", "function drawHostCaption("} {
		if !strings.Contains(wgViewJS, fn) {
			t.Errorf("wg_view.js has no %s — the shared glyph is what the count above is guarding", fn)
		}
	}
}

// Every lane that can place an endpoint asks the model who owns it. Stated as
// the call rather than the drawing because the mesh stack deliberately does not
// draw a frame — its rows are 28px apart and a rectangle per row would be a box
// around a box around nothing — so counting frames would read that lane as
// missing when it is correct.
func TestPlacementEveryLaneConsultsTheModel(t *testing.T) {
	for _, lane := range []struct{ fn, name string }{
		{"function drawMeshStacks(", "mesh stack"},
		{"function drawTopChips(", "hub-zone chip row"},
		{"function drawZones(", "far zone rows"},
		{"function drawHops(", "hop chips"},
	} {
		start := strings.Index(wgViewJS, lane.fn)
		if start < 0 {
			t.Fatalf("wg_view.js has no %s", lane.fn)
		}
		body := wgViewJS[start:]
		if end := strings.Index(body[1:], "\nfunction "); end >= 0 {
			body = body[:end+1]
		}
		if !strings.Contains(body, "place(N,") && !strings.Contains(body, "placedOn(") {
			t.Errorf("the %s lane never asks place()/placedOn() who owns its endpoints;\n"+
				"that is how %s drew no physical host while the other three did", lane.name, lane.fn)
		}
	}
}
