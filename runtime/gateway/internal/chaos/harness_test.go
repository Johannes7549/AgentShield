package chaos

import (
	"strings"
	"testing"
)

func TestCatalogPassesAndMissingResultFails(t *testing.T) {
	seen := map[string]bool{}
	for _, id := range Catalog() {
		seen[id] = true
		result := Run(id)
		if result.Status != "passed" {
			t.Fatalf("%s = %+v", id, result)
		}
		if strings.Contains(result.Reason, "missing result") {
			t.Fatalf("%s treated a missing result as a pass", id)
		}
	}
	if len(seen) != 12 {
		t.Fatalf("catalog = %d", len(seen))
	}
	missing := judge(false, true, "a dependency error fails closed")
	if missing.Status != "failed" || !strings.Contains(missing.Reason, "missing result") {
		t.Fatalf("missing = %+v", missing)
	}
	wrong := judge(true, false, "an action outside allow and approval is denied")
	if wrong.Status != "failed" || !strings.Contains(wrong.Reason, "not observed") {
		t.Fatalf("wrong = %+v", wrong)
	}
	if Run("not-a-scenario").Status != "error" {
		t.Fatal("unknown scenario")
	}
}
