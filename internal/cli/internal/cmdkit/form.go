package cmdkit

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// FindHost resolves the hostname before anything is written, so a typo fails
// with a name rather than a silent no-op on every step.
func FindHost(ctx context.Context, st InventoryLister, host string) (store.InventoryRow, error) {
	rows, err := st.ListInventory(ctx, "")
	if err != nil {
		return store.InventoryRow{}, err
	}
	for _, r := range rows {
		if r.Hostname == host {
			return r, nil
		}
	}
	return store.InventoryRow{}, fmt.Errorf("no host named %q in the inventory", host)
}

// StateOptions labels each state with what it means for the listing, because
// the words alone do not say which of them silence a red row and which do not.
//
// Nothing here marks the current value: the field is bound to a variable already
// holding it, and huh selects the option matching that. Setting it twice would
// be two mechanisms for one behaviour, and they can disagree.
// StateOptions are the words the database accepts, and only the words.
//
// The meanings live in stateMeanings rather than in the labels because the
// field is inline: it renders one value at a time, so a label carrying its own
// explanation would show one state's meaning and hide the other three.
func StateOptions() []huh.Option[string] {
	opts := make([]huh.Option[string], 0, len(store.HostStates))
	for _, s := range store.HostStates {
		opts = append(opts, huh.NewOption(s, s))
	}
	return opts
}

// InventoryLister is the slice of *store.Store that add reads.
//
// The jump-host check and the datacenter suggestions are the parts of this
// command most likely to be wrong, and both were reachable only with a live
// database behind them. Narrowing the dependency to the one method they use
// puts those branches under test; the alternative is trusting the branch that
// decides whether a host is reachable at all.
type InventoryLister interface {
	ListInventory(ctx context.Context, dc string) ([]store.InventoryRow, error)
}

func NonEmpty(what string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", what)
		}
		return nil
	}
}
