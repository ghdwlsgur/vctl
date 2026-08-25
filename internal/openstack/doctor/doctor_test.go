package doctor

import (
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/openstackapi"
)

// A missing credential field is a different problem from a missing credential,
// and the fix is different too.
func TestMissingCredFieldsNamesWhatIsAbsent(t *testing.T) {
	got := MissingCredFields(openstackapi.Credentials{AuthURL: "https://x", Username: "u"})
	joined := strings.Join(got, ",")
	for _, want := range []string{"password", "project_name"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing fields = %v, want %s named", got, want)
		}
	}
	if strings.Contains(joined, "auth_url") {
		t.Errorf("missing fields = %v, want the ones that are set left out", got)
	}
	if len(MissingCredFields(openstackapi.Credentials{
		AuthURL: "a", Username: "b", Password: "c", ProjectName: "d",
	})) != 0 {
		t.Error("a complete credential was reported as incomplete")
	}
}
