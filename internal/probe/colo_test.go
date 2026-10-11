package probe

import "testing"

// Cloudflare answers id.server with values like "dme04" (seen on a real
// network), older documentation shows "FRA".
func TestColoCode(t *testing.T) {
	for _, s := range []string{"FRA", "dme04", "AMS1", "led"} {
		if !coloRe.MatchString(s) {
			t.Errorf("%q should be a colo code", s)
		}
	}
	for _, s := range []string{"", "nsdi", "198.51.100.1", "fr", "resolver1.example"} {
		if coloRe.MatchString(s) {
			t.Errorf("%q should not be a colo code", s)
		}
	}
}
