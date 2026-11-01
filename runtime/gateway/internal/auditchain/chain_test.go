package auditchain

import (
	"encoding/json"
	"testing"
	"time"
)

func sample(payload string, at time.Time) Event {
	return Event{
		EventID:         "11111111-1111-1111-1111-111111111111",
		OrganizationID:  "22222222-2222-2222-2222-222222222222",
		EventType:       "authorization.decided",
		OccurredAt:      at,
		PayloadRedacted: json.RawMessage(payload),
	}
}

func TestHashIgnoresObjectKeyOrder(t *testing.T) {
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.FixedZone("EEST", 3*60*60))
	left, err := Hash(GenesisPrevHash, sample(`{"b":1,"a":2}`, at))
	if err != nil {
		t.Fatal(err)
	}
	right, err := Hash(GenesisPrevHash, sample(`{"a":2,"b":1}`, at))
	if err != nil {
		t.Fatal(err)
	}
	if left.EventHash != right.EventHash {
		t.Fatalf("hashes differ: %s %s", left.EventHash, right.EventHash)
	}
	if err := Verify(GenesisPrevHash, sample(`{"a":2,"b":1}`, at), left.EventHash); err != nil {
		t.Fatal(err)
	}
}

func TestChainLinksAndDetectsTampering(t *testing.T) {
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	first, err := Hash(GenesisPrevHash, sample(`{"outcome":"deny"}`, at))
	if err != nil {
		t.Fatal(err)
	}
	secondEvent := sample(`{"outcome":"allow"}`, at.Add(time.Second))
	secondEvent.EventID = "33333333-3333-3333-3333-333333333333"
	second, err := Hash(first.EventHash, secondEvent)
	if err != nil {
		t.Fatal(err)
	}
	if second.PrevHash != first.EventHash {
		t.Fatal("chain did not link")
	}
	if err := Verify(first.EventHash, secondEvent, second.EventHash); err != nil {
		t.Fatal(err)
	}
	if err := Verify(first.EventHash, sample(`{"outcome":"allow"}`, at.Add(time.Second)), second.EventHash); err == nil {
		t.Fatal("tampered event verified")
	}
}

func TestHashRejectsUppercasePrevHash(t *testing.T) {
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	if _, err := Hash("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", sample(`{}`, at)); err == nil {
		t.Fatal("accepted an uppercase previous hash")
	}
}

func TestCanonicalSortsPolicyKeys(t *testing.T) {
	got, err := Canonical(map[string]any{
		"permissions": map[string]any{
			"denied":            []any{"database.export"},
			"allowed":           []any{"sample.echo"},
			"approval_required": []any{"email.send"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"permissions":{"allowed":["sample.echo"],"approval_required":["email.send"],"denied":["database.export"]}}`
	if string(got) != want {
		t.Fatalf("canonical = %s", got)
	}
}
