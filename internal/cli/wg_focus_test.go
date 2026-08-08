package cli

import "testing"

// The dim pass, rule by rule.
//
// Until now nothing tested this. The focus tests asserted on focusClosure — the
// set of interfaces, nodes and edges a selection covers — and stopped there,
// which is a test of what the selection *means* and not of what the screen
// *does* with it. Every bug in this area was in the second half: the closure was
// right and the wrong things stayed lit. Four attempts at one of them landed and
// were reverted because `make check` passed each time.
//
// focusVerdict reads a plain dataset object, so each rule below is stated as the
// tag combination that produces it. What the rules add up to on real SVG is
// measured by scripts/wg-dashboard-check.mjs; these pin the precedence.

// focusJS sets up a selection and a helper. `V(tags, inherited)` is one
// element's verdict, `D(tags, inherited, leaf, classes)` is whether it dims.
const focusJS = `
const focus={
  ifaces:new Set(["wg1"]),
  nodes:new Set(["seoul-gw"]),
  edges:new Set(["e-hub-seoul"]),
  hubIfaces:new Set(["wg1"]),
  cidrs:new Set(["192.168.201.0/24"]),
};
const V=(data,inherited=false)=>focusVerdict(data,inherited,focus);
const D=(data,{inherited=false,leaf=true,classes=[]}={})=>
  focusPass({data,classes,leaf},inherited,focus,"wg1").dim;
`

// keep means "always part of the picture", and it has to reach the children or
// it means nothing: the hub is one group whose box, title and address are
// untagged children of it, so a keep that stopped at the group left the hub
// drawn as an empty outline during a focus on its own interface.
func TestFocusKeepSurvivesAndReachesItsChildren(t *testing.T) {
	got := runModelJS(t, focusJS+`
console.log(JSON.stringify([
  V({keep:"1"}),                 // the hub group itself
  V({},true),                    // its untagged title, inheriting that verdict
  D({keep:"1"}),                 // and it never dims
]));
`)
	if want := `[true,true,false]`; got != want {
		t.Errorf("keep = %s, want %s", got, want)
	}
}

// An explicit tag beats an inherited verdict in both directions, so a wg3 glyph
// on a node wg0 also reaches goes dark during a wg0 focus.
func TestFocusAnExplicitTagOverridesWhatTheParentDecided(t *testing.T) {
	got := runModelJS(t, focusJS+`
console.log(JSON.stringify([
  V({ifc:"wg3"},true),   // inside a matched group, but it is not this interface
  V({ifc:"wg1"},false),  // inside a dimmed group, but it IS this interface
]));
`)
	if want := `[false,true]`; got != want {
		t.Errorf("explicit tag = %s, want %s", got, want)
	}
}

// An interface tag that does not match is not the last word when the same group
// also names nodes or edges that are in focus.
//
// A tunnel's far end is drawn by the chip that owns it — tagged with the
// interface facing the hub, which is a different name — so short-circuiting on
// the interface dimmed the node at the other end of the very tunnel being
// focused. Measured at the time: wg-seoul lit its tunnel and its hub and nothing
// else.
func TestFocusAForeignInterfaceTagStillMatchesOnAFocusedEdgeOrNode(t *testing.T) {
	got := runModelJS(t, focusJS+`
console.log(JSON.stringify([
  V({ifc:"wg-seoul",eids:'["e-hub-seoul"]'}),   // the far end of the focused tunnel
  V({ifc:"wg-seoul",nodes:'["seoul-gw"]'}),     // the node that tunnel lands on
  V({ifc:"wg-seoul",eids:'["e-other"]'}),       // an unrelated tunnel on the same chip
]));
`)
	if want := `[true,true,false]`; got != want {
		t.Errorf("interface tag with precise data = %s, want %s", got, want)
	}
}

// A routed-network band is semantic, not owned by the first interface that
// happened to create it. The same CIDR can later receive wg-seoul/wg1 routes, so
// CIDR focus must beat the band's initial data-ifs value.
func TestFocusACidrBandIsOwnedByItsRangeNotByWhoDrewIt(t *testing.T) {
	got := runModelJS(t, focusJS+`
console.log(JSON.stringify([
  V({cidr:"192.168.201.0/24",ifs:"wg-seoul"}),  // drawn by wg-seoul, routed over wg1
  V({cidr:"10.9.0.0/24",ifs:"wg1"}),            // drawn by wg1, not in this closure
]));
`)
	if want := `[true,false]`; got != want {
		t.Errorf("cidr band = %s, want %s", got, want)
	}
}

// No tag at all means "ask my parent".
//
// The pass used to be a flat querySelectorAll where each element judged itself
// alone and anything untagged was skipped outright, so untagged geometry never
// dimmed. Selecting wg1 dimmed the few tagged things and left the wg3 mesh lit
// beside it — ten beads with nothing to do with wg1 — which reads as "a few dots
// changed colour" instead of isolating an interface.
func TestFocusUntaggedGeometryInheritsInsteadOfStayingLit(t *testing.T) {
	got := runModelJS(t, focusJS+`
console.log(JSON.stringify([
  D({},{inherited:false}),  // inside a dimmed group: dims with it
  D({},{inherited:true}),   // inside a matched group: stays
]));
`)
	if want := `[true,false]`; got != want {
		t.Errorf("untagged element = %s, want %s", got, want)
	}
}

// An element with children never dims itself. Dimming a container takes its
// matched descendants down with it, which blacked out the entire diagram the
// first time this was attempted.
func TestFocusAContainerNeverDimsItself(t *testing.T) {
	got := runModelJS(t, focusJS+`
console.log(JSON.stringify([
  D({ifc:"wg3"},{leaf:false}),  // an unmatched group holding matched glyphs
  D({ifc:"wg3"},{leaf:true}),   // the same tag on a leaf
]));
`)
	if want := `[false,true]`; got != want {
		t.Errorf("container = %s, want %s", got, want)
	}
}

// Chrome is the drawing's frame rather than anything on it: lane headings, the
// zone boxes, the NAT divider. A filter that hides where "EDGE / NAT" was does
// not isolate anything.
func TestFocusChromeNeverDims(t *testing.T) {
	got := runModelJS(t, focusJS+`
const out=[...CHROME_CLASSES].map(c=>D({},{classes:[c]}));
out.push(D({},{classes:["tun"]}));   // not chrome: a tunnel does dim
console.log(JSON.stringify(out));
`)
	if want := `[false,false,false,false,false,false,false,true]`; got != want {
		t.Errorf("chrome = %s, want %s", got, want)
	}
}

// With nothing selected nothing dims, whatever the tags say.
func TestFocusNothingDimsWithNoSelection(t *testing.T) {
	got := runModelJS(t, focusJS+`
console.log(JSON.stringify(focusPass({data:{ifc:"wg3"},classes:["tun"],leaf:true},false,focus,null).dim));
`)
	if got != "false" {
		t.Errorf("an element dimmed with no interface selected: %s", got)
	}
}
