// Package strutil holds tiny string helpers shared across packages.
package strutil

// FirstNonEmpty returns the first non-empty argument, or "" if all are empty.
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
