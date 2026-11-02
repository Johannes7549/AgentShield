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

func TestApprovalDecisionVector(t *testing.T) {
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	link, err := Hash(GenesisPrevHash, Event{
		EventID:         "11111111-1111-4111-8111-111111111111",
		OrganizationID:  "22222222-2222-4222-8222-222222222222",
		EventType:       "approval.decided",
		OccurredAt:      at,
		PayloadRedacted: []byte(`{"approval_id":"33333333-3333-4333-8333-333333333333","decision":"approved"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := at.UTC().Format("2006-01-02T15:04:05.000000000Z"); got != "2026-11-02T12:00:00.000000000Z" {
		t.Fatalf("occurred_at = %s", got)
	}
	if link.PayloadHash != "e172888566ddcc86ced6b953f71bdf80be916b1b9c09b2f068581a55c35f6b39" {
		t.Fatalf("payload hash = %s", link.PayloadHash)
	}
	if link.EventHash != "1e32b77235a3c79d4539a33599dbed607617605e2e2bc8f032978324c2d76df6" {
		t.Fatalf("event hash = %s", link.EventHash)
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
