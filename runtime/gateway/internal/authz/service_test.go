package authz

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/agentshield/agentshield/runtime/gateway/internal/nonce"
	"github.com/agentshield/agentshield/runtime/identity"
	"github.com/agentshield/agentshield/runtime/policy-engine"
)

const (
	testAgent = "11111111-1111-4111-8111-111111111111"
	testOrg   = "22222222-2222-4222-8222-222222222222"
	otherOrg  = "33333333-3333-4333-8333-333333333333"
	testExec  = "44444444-4444-4444-8444-444444444444"
)

type memDirectory struct {
	principal Principal
}

func (d memDirectory) Lookup(context.Context, string) (Principal, error) {
	return d.principal, nil
}

type memPolicies struct {
	organization *policy.Source
	agent        *policy.Source
	err          error
}

func (m memPolicies) Load(context.Context, string, string) (*policy.Source, *policy.Source, error) {
	return m.organization, m.agent, m.err
}

type memStore struct {
	records []Record
}

func (m *memStore) Record(_ context.Context, record Record) (Saved, error) {
	m.records = append(m.records, record)
	return Saved{
		DecisionID:  "55555555-5555-4555-8555-555555555555",
		Outcome:     string(record.Decision.Outcome),
		Explanation: record.Decision.Explanation,
	}, nil
}

func (m *memStore) Load(context.Context, string, string, string) (Executable, error) {
	return Executable{}, ErrNotFound
}

func (m *memStore) Finish(context.Context, Executable, func() (map[string]any, error)) (ExecuteResult, error) {
	return ExecuteResult{}, errors.New("execute was not expected")
}

type memNonce struct {
	used map[string]bool
}

func (m *memNonce) Reserve(_ context.Context, agentID string, value string) error {
	if m.used == nil {
		m.used = map[string]bool{}
	}
	key := agentID + ":" + value
	if m.used[key] {
		return nonce.ErrReplay
	}
	m.used[key] = true
	return nil
}

func testService(t *testing.T, policies memPolicies, store *memStore) (*Service, ed25519.PrivateKey, time.Time) {
	t.Helper()
	public, private := testKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	return &Service{
		Directory: memDirectory{principal: Principal{
			AgentID:          testAgent,
			OrganizationID:   testOrg,
			Status:           "active",
			CredentialStatus: "active",
			PublicKey:        public,
		}},
		Policies: policies,
		Store:    store,
		Nonces:   &memNonce{},
		Now:      func() time.Time { return now },
	}, private, now
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	return public, private
}

func signedRequest(t *testing.T, private ed25519.PrivateKey, now time.Time, org string, operation string, nonceValue string, key string) ([]byte, Headers) {
	t.Helper()
	body := fmt.Sprintf(
		`{"agent_id":"%s","arguments":{},"execution_id":"%s","idempotency_key":"%s","operation":"%s","organization_id":"%s","requested_at":"%s","resource":"ticket-1","tool_name":"sample.echo"}`,
		testAgent, testExec, key, operation, org, now.Format(time.RFC3339),
	)
	signature, err := identity.Sign(private, now.Unix(), nonceValue, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(body), Headers{
		AgentID:   testAgent,
		Timestamp: strconv.FormatInt(now.Unix(), 10),
		Nonce:     nonceValue,
		Signature: signature,
	}
}

func TestAuthorizeSecurityDecisions(t *testing.T) {
	org := &policy.Source{
		PolicyID: "org-policy", VersionID: "org-version", Version: 1,
		Document: policy.Document{Permissions: policy.Permissions{
			Allowed: []string{"sample.echo"}, Denied: []string{"database.export"}, ApprovalRequired: []string{"email.send"},
		}},
	}
	store := &memStore{}
	service, private, now := testService(t, memPolicies{organization: org}, store)

	t.Run("bad signature records nothing", func(t *testing.T) {
		body, headers := signedRequest(t, private, now, testOrg, "sample.echo", "nonce-value-000001", "idempotency-key-01")
		body = bytes.Replace(body, []byte("ticket-1"), []byte("ticket-2"), 1)
		_, err := service.Authorize(context.Background(), body, headers)
		var failure *Failure
		if !errors.As(err, &failure) || failure.Status != 401 || len(store.records) != 0 {
			t.Fatalf("err = %v records = %d", err, len(store.records))
		}
	})

	t.Run("explicit deny", func(t *testing.T) {
		body, headers := signedRequest(t, private, now, testOrg, "database.export", "nonce-value-000002", "idempotency-key-02")
		result, err := service.Authorize(context.Background(), body, headers)
		if err != nil || result.Outcome != "deny" || result.Explanation.Reason != "explicit deny" {
			t.Fatalf("result = %+v err = %v", result, err)
		}
	})

	t.Run("default deny", func(t *testing.T) {
		body, headers := signedRequest(t, private, now, testOrg, "tickets.read", "nonce-value-000003", "idempotency-key-03")
		result, err := service.Authorize(context.Background(), body, headers)
		if err != nil || result.Outcome != "deny" || result.Explanation.Reason != "default deny" {
			t.Fatalf("result = %+v err = %v", result, err)
		}
	})

	t.Run("allow", func(t *testing.T) {
		body, headers := signedRequest(t, private, now, testOrg, "sample.echo", "nonce-value-000004", "idempotency-key-04")
		result, err := service.Authorize(context.Background(), body, headers)
		if err != nil || result.Outcome != "allow" {
			t.Fatalf("result = %+v err = %v", result, err)
		}
	})

	t.Run("require approval", func(t *testing.T) {
		body, headers := signedRequest(t, private, now, testOrg, "email.send", "nonce-value-000005", "idempotency-key-05")
		result, err := service.Authorize(context.Background(), body, headers)
		if err != nil || result.Outcome != "require_approval" {
			t.Fatalf("result = %+v err = %v", result, err)
		}
	})

	t.Run("organization mismatch is recorded under the agent org", func(t *testing.T) {
		before := len(store.records)
		body, headers := signedRequest(t, private, now, otherOrg, "sample.echo", "nonce-value-000006", "idempotency-key-06")
		result, err := service.Authorize(context.Background(), body, headers)
		if err != nil || result.Outcome != "deny" || result.Explanation.Reason != "organization claim does not match the authenticated agent" {
			t.Fatalf("result = %+v err = %v", result, err)
		}
		if store.records[before].OrganizationID != testOrg {
			t.Fatalf("stored org = %s", store.records[before].OrganizationID)
		}
	})

	t.Run("replay", func(t *testing.T) {
		body, headers := signedRequest(t, private, now, testOrg, "sample.echo", "nonce-value-000007", "idempotency-key-07")
		if _, err := service.Authorize(context.Background(), body, headers); err != nil {
			t.Fatal(err)
		}
		before := len(store.records)
		_, err := service.Authorize(context.Background(), body, headers)
		var failure *Failure
		if !errors.As(err, &failure) || failure.Code != "unauthenticated" || len(store.records) != before {
			t.Fatalf("err = %v records grew = %v", err, len(store.records) != before)
		}
	})

	t.Run("human session is rejected", func(t *testing.T) {
		body, headers := signedRequest(t, private, now, testOrg, "sample.echo", "nonce-value-000008", "idempotency-key-08")
		headers.Authorization = "Bearer human-token"
		before := len(store.records)
		_, err := service.Authorize(context.Background(), body, headers)
		var failure *Failure
		if !errors.As(err, &failure) || failure.Status != 401 || len(store.records) != before {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestPolicyLoadFailureIsDeny(t *testing.T) {
	store := &memStore{}
	service, private, now := testService(t, memPolicies{err: errors.New("database down")}, store)
	body, headers := signedRequest(t, private, now, testOrg, "sample.echo", "nonce-value-000009", "idempotency-key-09")
	result, err := service.Authorize(context.Background(), body, headers)
	if err != nil || result.Outcome != "deny" || result.Explanation.Reason != "policy load failed" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

func TestExecuteDoesNotRunDeniedCall(t *testing.T) {
	store := &executeStore{call: Executable{
		DecisionID: "55555555-5555-4555-8555-555555555555", Outcome: "deny",
		ToolName: "sample.echo", Operation: "sample.echo", IdempotencyKey: "idempotency-key-10",
	}}
	service, private, now := testService(t, memPolicies{}, &memStore{})
	service.Store = store
	body := []byte(`{"decision_id":"55555555-5555-4555-8555-555555555555","idempotency_key":"idempotency-key-10"}`)
	signature, err := identity.Sign(private, now.Unix(), "nonce-value-000010", body)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Execute(context.Background(), body, Headers{
		AgentID: testAgent, Timestamp: strconv.FormatInt(now.Unix(), 10),
		Nonce: "nonce-value-000010", Signature: signature,
	})
	var failure *Failure
	if !errors.As(err, &failure) || failure.Status != 403 {
		t.Fatalf("err = %v", err)
	}
	store.call.Outcome = "allow"
	store.call.ToolName = "tickets.search"
	body = []byte(`{"decision_id":"55555555-5555-4555-8555-555555555555","idempotency_key":"idempotency-key-10"}`)
	signature, err = identity.Sign(private, now.Unix(), "nonce-value-000011", body)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Execute(context.Background(), body, Headers{
		AgentID: testAgent, Timestamp: strconv.FormatInt(now.Unix(), 10),
		Nonce: "nonce-value-000011", Signature: signature,
	})
	if !errors.As(err, &failure) || failure.Status != 501 {
		t.Fatalf("unsupported tool err = %v", err)
	}
	if store.finished != 0 {
		t.Fatalf("finish calls = %d", store.finished)
	}
}

func TestExecuteConsumesOnlyAPresentedApproval(t *testing.T) {
	store := &executeStore{call: Executable{
		DecisionID: "55555555-5555-4555-8555-555555555555", Outcome: "require_approval",
		ToolName: "sample.echo", Operation: "sample.echo", IdempotencyKey: "idempotency-key-10",
	}}
	service, private, now := testService(t, memPolicies{}, &memStore{})
	service.Store = store
	body := []byte(`{"decision_id":"55555555-5555-4555-8555-555555555555","idempotency_key":"idempotency-key-10"}`)
	headers := signedHeaders(t, private, now, "nonce-value-000012", body)
	_, err := service.Execute(context.Background(), body, headers)
	var failure *Failure
	if !errors.As(err, &failure) || failure.Code != "approval_required" || store.finished != 0 {
		t.Fatalf("err = %v finished = %d", err, store.finished)
	}
	body = []byte(`{"approval_id":"66666666-6666-4666-8666-666666666666","decision_id":"55555555-5555-4555-8555-555555555555","idempotency_key":"idempotency-key-10"}`)
	headers = signedHeaders(t, private, now, "nonce-value-000013", body)
	result, err := service.Execute(context.Background(), body, headers)
	if err != nil || result.Adapter != "sample.echo" || store.finished != 1 || store.approvalID != "66666666-6666-4666-8666-666666666666" {
		t.Fatalf("result = %+v err = %v finished = %d approval = %s", result, err, store.finished, store.approvalID)
	}
}

func signedHeaders(t *testing.T, private ed25519.PrivateKey, now time.Time, nonce string, body []byte) Headers {
	t.Helper()
	signature, err := identity.Sign(private, now.Unix(), nonce, body)
	if err != nil {
		t.Fatal(err)
	}
	return Headers{
		AgentID: testAgent, Timestamp: strconv.FormatInt(now.Unix(), 10),
		Nonce: nonce, Signature: signature,
	}
}

type executeStore struct {
	call       Executable
	finished   int
	approvalID string
}

func (s *executeStore) Record(context.Context, Record) (Saved, error) {
	return Saved{}, errors.New("unexpected record")
}

func (s *executeStore) Load(context.Context, string, string, string) (Executable, error) {
	return s.call, nil
}

func (s *executeStore) Finish(_ context.Context, call Executable, run func() (map[string]any, error)) (ExecuteResult, error) {
	s.finished++
	s.approvalID = call.ApprovalID
	if _, err := run(); err != nil {
		return ExecuteResult{}, err
	}
	return ExecuteResult{DecisionID: call.DecisionID, Outcome: "allow", Adapter: "sample.echo"}, nil
}
