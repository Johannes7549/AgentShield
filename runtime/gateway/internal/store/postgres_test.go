package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agentshield/agentshield/runtime/gateway/internal/auditchain"
	"github.com/agentshield/agentshield/runtime/gateway/internal/authz"
	"github.com/agentshield/agentshield/runtime/gateway/internal/idgen"
	"github.com/agentshield/agentshield/runtime/gateway/internal/jsondoc"
	"github.com/agentshield/agentshield/runtime/identity"
	"github.com/agentshield/agentshield/runtime/policy-engine"
)

func TestRecordDecisionRollsBack(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		url = "postgres://agentshield:agentshield@127.0.0.1:5432/agentshield?sslmode=disable"
	}
	if !strings.Contains(url, "127.0.0.1") && !strings.Contains(url, "localhost") {
		t.Skip("refusing a non-local database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := Open(ctx, url)
	if err != nil {
		t.Skip(err)
	}
	defer pool.Close()
	pingCtx, pingCancel := context.WithTimeout(context.Background(), time.Second)
	err = pool.Ping(pingCtx)
	pingCancel()
	if err != nil {
		t.Skip("postgres is not available")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	orgID, err := idgen.New()
	if err != nil {
		t.Fatal(err)
	}
	agentID, err := idgen.New()
	if err != nil {
		t.Fatal(err)
	}
	executionID, err := idgen.New()
	if err != nil {
		t.Fatal(err)
	}
	public, _ := testKey()
	fingerprint, err := identity.Fingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'Phase 1', $2)`, orgID, "p1-"+orgID[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agents (id, organization_id, name, framework)
		VALUES ($1, $2, 'sample', 'python')`, agentID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_credentials (agent_id, organization_id, public_key, public_key_fingerprint)
		VALUES ($1, $2, $3, $4)`, agentID, orgID, []byte(public), fingerprint); err != nil {
		t.Fatal(err)
	}
	document := []byte(`{"permissions":{"allowed":["sample.echo"],"approval_required":["email.send"],"denied":["database.export"]}}`)
	parsed, err := jsondoc.Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := auditchain.Canonical(parsed)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	var policyID, versionID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO security_policies (organization_id, name, scope, status)
		VALUES ($1, 'sample', 'organization', 'active') RETURNING id::text`, orgID).Scan(&policyID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO policy_versions (policy_id, organization_id, version, document, document_hash)
		VALUES ($1, $2, 1, $3::jsonb, $4) RETURNING id::text`,
		policyID, orgID, string(canonical), hex.EncodeToString(sum[:])).Scan(&versionID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE security_policies SET current_version_id = $1 WHERE id = $2`, versionID, policyID); err != nil {
		t.Fatal(err)
	}

	postgres := New(tx)
	directory := Directory{DB: postgres}
	decisions := Decisions{DB: postgres}
	principal, err := directory.Lookup(ctx, agentID)
	if err != nil {
		t.Fatal(err)
	}
	if principal.OrganizationID != orgID || principal.CredentialStatus != "active" {
		t.Fatalf("principal = %+v", principal)
	}
	organization, agentPolicy, err := postgres.Load(ctx, orgID, agentID)
	if err != nil || organization == nil || agentPolicy != nil {
		t.Fatalf("policies org=%v agent=%v err=%v", organization, agentPolicy, err)
	}
	decision, err := policy.Evaluate(organization, nil, "database.export", "customers")
	if err != nil || decision.Outcome != policy.OutcomeDeny {
		t.Fatalf("decision = %+v %v", decision, err)
	}
	saved, err := decisions.Record(ctx, authz.Record{
		OrganizationID: orgID, AgentID: agentID, ExecutionID: executionID,
		IdempotencyKey: "idempotency-key-db", ToolName: "sample.echo", Operation: "database.export",
		Resource: "customers", ArgumentsHash: hex.EncodeToString(sum[:]), ArgumentsRedacted: []byte(`{}`),
		RequestedAt: time.Now().UTC(), Decision: decision, RawBodyHash: hex.EncodeToString(sum[:]), Risk: "low",
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Outcome != "deny" {
		t.Fatalf("saved = %+v", saved)
	}
	var sequence int
	var prev string
	if err := tx.QueryRow(ctx, `SELECT sequence, prev_hash FROM audit_chain WHERE organization_id = $1`, orgID).Scan(&sequence, &prev); err != nil {
		t.Fatal(err)
	}
	if sequence != 1 || prev != auditchain.GenesisPrevHash {
		t.Fatalf("chain sequence = %d prev = %s", sequence, prev)
	}

	approval, err := policy.Evaluate(organization, nil, "email.send", "customer-1")
	if err != nil {
		t.Fatal(err)
	}
	secondExecution, err := idgen.New()
	if err != nil {
		t.Fatal(err)
	}
	approved, err := decisions.Record(ctx, authz.Record{
		OrganizationID: orgID, AgentID: agentID, ExecutionID: secondExecution,
		IdempotencyKey: "idempotency-key-ap", ToolName: "sample.echo", Operation: "email.send",
		Resource: "customer-1", ArgumentsHash: hex.EncodeToString(sum[:]), ArgumentsRedacted: []byte(`{}`),
		RequestedAt: time.Now().UTC(), Decision: approval, RawBodyHash: strings.Repeat("ab", 32), Risk: "medium",
	})
	if err != nil {
		t.Fatal(err)
	}
	if approved.Outcome != "require_approval" || approved.ApprovalID == "" {
		t.Fatalf("approval = %+v", approved)
	}
	replayed, err := decisions.Record(ctx, authz.Record{
		OrganizationID: orgID, AgentID: agentID, ExecutionID: secondExecution,
		IdempotencyKey: "idempotency-key-ap", ToolName: "sample.echo", Operation: "email.send",
		Resource: "customer-1", ArgumentsHash: hex.EncodeToString(sum[:]), ArgumentsRedacted: []byte(`{}`),
		RequestedAt: time.Now().UTC(), Decision: policy.Deny("should not replace"), RawBodyHash: strings.Repeat("ab", 32), Risk: "low",
	})
	if err != nil || replayed.DecisionID != approved.DecisionID || replayed.Outcome != "require_approval" {
		t.Fatalf("replayed = %+v err = %v", replayed, err)
	}

	allowed, err := policy.Evaluate(organization, nil, "sample.echo", "demo")
	if err != nil || allowed.Outcome != policy.OutcomeAllow {
		t.Fatalf("allow = %+v %v", allowed, err)
	}
	echoExecution, err := idgen.New()
	if err != nil {
		t.Fatal(err)
	}
	echoSaved, err := decisions.Record(ctx, authz.Record{
		OrganizationID: orgID, AgentID: agentID, ExecutionID: echoExecution,
		IdempotencyKey: "idempotency-key-echo", ToolName: "sample.echo", Operation: "sample.echo",
		Resource: "demo", ArgumentsHash: hex.EncodeToString(sum[:]), ArgumentsRedacted: []byte(`{}`),
		RequestedAt: time.Now().UTC(), Decision: allowed, RawBodyHash: strings.Repeat("cd", 32), Risk: "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	call, err := decisions.Load(ctx, orgID, agentID, echoSaved.DecisionID)
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	executed, err := decisions.Finish(ctx, call, func() (map[string]any, error) {
		runs++
		return map[string]any{"adapter": "sample.echo", "label": "sample adapter with no external side effect"}, nil
	})
	if err != nil || executed.Adapter != "sample.echo" || runs != 1 {
		t.Fatalf("executed = %+v runs = %d err = %v", executed, runs, err)
	}
	again, err := decisions.Finish(ctx, call, func() (map[string]any, error) {
		runs++
		return map[string]any{}, nil
	})
	if err != nil || again.Adapter != "sample.echo" || runs != 1 {
		t.Fatalf("replay execute = %+v runs = %d err = %v", again, runs, err)
	}

	approvalCall, err := decisions.Load(ctx, orgID, agentID, approved.DecisionID)
	if err != nil {
		t.Fatal(err)
	}
	approvalCall.ApprovalID = approved.ApprovalID
	consumedRuns := 0
	_, err = decisions.Finish(ctx, approvalCall, func() (map[string]any, error) {
		consumedRuns++
		return map[string]any{"label": "should not run"}, nil
	})
	if !errors.Is(err, authz.ErrApprovalPending) || consumedRuns != 0 {
		t.Fatalf("pending consume err = %v runs = %d", err, consumedRuns)
	}
	passwordHash := strings.Repeat("x", 60)
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, display_name)
		VALUES ($1, $2, $3, 'Same As Agent')`, agentID, "agent-"+agentID[:8]+"@example.com", passwordHash); err != nil {
		t.Fatal(err)
	}
	approverID, err := idgen.New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, display_name)
		VALUES ($1, $2, $3, 'Approver')`, approverID, "approver-"+approverID[:8]+"@example.com", passwordHash); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE approval_requests
		SET status = 'approved', decided_by = $2, decided_at = now()
		WHERE id = $1`, approved.ApprovalID, agentID); err != nil {
		t.Fatal(err)
	}
	_, err = decisions.Finish(ctx, approvalCall, func() (map[string]any, error) {
		consumedRuns++
		return map[string]any{"label": "should not run"}, nil
	})
	if !errors.Is(err, authz.ErrApprovalBinding) || consumedRuns != 0 {
		t.Fatalf("self-approval err = %v runs = %d", err, consumedRuns)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE approval_requests SET decided_by = $2 WHERE id = $1`, approved.ApprovalID, approverID); err != nil {
		t.Fatal(err)
	}
	consumed, err := decisions.Finish(ctx, approvalCall, func() (map[string]any, error) {
		consumedRuns++
		return map[string]any{"label": "sample adapter with no external side effect"}, nil
	})
	if err != nil || consumed.Adapter != "sample.echo" || consumedRuns != 1 {
		t.Fatalf("consumed = %+v runs = %d err = %v", consumed, consumedRuns, err)
	}
	replayedConsumption, err := decisions.Finish(ctx, approvalCall, func() (map[string]any, error) {
		consumedRuns++
		return map[string]any{}, nil
	})
	if err != nil || replayedConsumption.Adapter != "sample.echo" || consumedRuns != 1 {
		t.Fatalf("replayed consumption = %+v runs = %d err = %v", replayedConsumption, consumedRuns, err)
	}
	var approvalStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, approved.ApprovalID).Scan(&approvalStatus); err != nil {
		t.Fatal(err)
	}
	if approvalStatus != "consumed" {
		t.Fatalf("approval status = %s", approvalStatus)
	}

	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE id = $1`, orgID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("organizations = %d", count)
	}
	_, err = tx.Exec(ctx, `UPDATE security_events SET event_type = 'tamper' WHERE organization_id = $1`, orgID)
	if err == nil {
		t.Fatal("append-only event accepted an update")
	}
}

func testKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	private := ed25519.NewKeyFromSeed(seed)
	return private.Public().(ed25519.PublicKey), private
}
