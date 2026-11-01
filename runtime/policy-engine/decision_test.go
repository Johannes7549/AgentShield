package policy

import "testing"

func TestParseOutcome(t *testing.T) {
	for _, value := range []string{"allow", "deny", "require_approval"} {
		got, err := ParseOutcome(value)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != value {
			t.Fatalf("parsed %q as %q", value, got)
		}
	}
	for _, value := range []string{"", "ALLOW", "permit", "approve"} {
		if _, err := ParseOutcome(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestDenyIsClosed(t *testing.T) {
	decision := Deny("no matching policy")
	if decision.Outcome != OutcomeDeny {
		t.Fatalf("outcome = %s", decision.Outcome)
	}
	if decision.Explanation.Reason == "" {
		t.Fatal("missing reason")
	}
}
