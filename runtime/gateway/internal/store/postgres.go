package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/agentshield/agentshield/runtime/gateway/internal/adapter"
	"github.com/agentshield/agentshield/runtime/gateway/internal/auditchain"
	"github.com/agentshield/agentshield/runtime/gateway/internal/authz"
	"github.com/agentshield/agentshield/runtime/gateway/internal/idgen"
	"github.com/agentshield/agentshield/runtime/gateway/internal/jsondoc"
	"github.com/agentshield/agentshield/runtime/gateway/internal/limits"
	"github.com/agentshield/agentshield/runtime/policy-engine"
)

type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Postgres struct {
	db DB
}

func New(db DB) *Postgres {
	return &Postgres{db: db}
}

func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("DATABASE_URL is invalid")
	}
	config.MaxConns = 10
	config.ConnConfig.ConnectTimeout = 3 * time.Second
	return pgxpool.NewWithConfig(ctx, config)
}

func (p *Postgres) Lookup(ctx context.Context, agentID string) (authz.Principal, error) {
	rows, err := p.db.Query(ctx, `
		SELECT a.organization_id::text, a.status, c.public_key, c.status, c.not_before, c.not_after
		FROM agents a
		LEFT JOIN agent_credentials c
		  ON c.agent_id = a.id AND c.organization_id = a.organization_id
		WHERE a.id = $1
		ORDER BY c.created_at DESC NULLS LAST`, agentID)
	if err != nil {
		return authz.Principal{}, err
	}
	defer rows.Close()

	var principal authz.Principal
	var active []credential
	var latest *credential
	found := false
	for rows.Next() {
		var organizationID, status string
		var publicKey []byte
		var credentialStatus *string
		var notBefore *time.Time
		var notAfter *time.Time
		if err := rows.Scan(&organizationID, &status, &publicKey, &credentialStatus, &notBefore, &notAfter); err != nil {
			return authz.Principal{}, err
		}
		found = true
		principal.AgentID = agentID
		principal.OrganizationID = organizationID
		principal.Status = status
		if credentialStatus == nil || len(publicKey) != 32 {
			continue
		}
		item := credential{
			status:    *credentialStatus,
			publicKey: publicKey,
			notBefore: valueOrZero(notBefore),
			notAfter:  notAfter,
		}
		if latest == nil {
			copyItem := item
			latest = &copyItem
		}
		if item.active(time.Now()) {
			active = append(active, item)
		}
	}
	if err := rows.Err(); err != nil {
		return authz.Principal{}, err
	}
	if !found {
		return authz.Principal{}, authz.ErrNotFound
	}
	switch len(active) {
	case 1:
		principal.CredentialStatus = "active"
		principal.PublicKey = active[0].publicKey
		return principal, nil
	case 0:
		if latest == nil {
			return authz.Principal{}, authz.ErrNotFound
		}
		principal.CredentialStatus = latest.status
		principal.PublicKey = latest.publicKey
		return principal, nil
	default:
		return authz.Principal{}, errors.New("multiple active credentials")
	}
}

func (p *Postgres) Load(ctx context.Context, organizationID string, agentID string) (*policy.Source, *policy.Source, error) {
	organization, err := p.onePolicy(ctx, `
		SELECT p.id::text, v.id::text, v.version, v.document::text, v.document_hash
		FROM security_policies p
		JOIN policy_versions v
		  ON v.id = p.current_version_id AND v.organization_id = p.organization_id
		WHERE p.organization_id = $1 AND p.status = 'active' AND p.scope = 'organization'`, organizationID)
	if err != nil {
		return nil, nil, err
	}
	agent, err := p.onePolicy(ctx, `
		SELECT p.id::text, v.id::text, v.version, v.document::text, v.document_hash
		FROM security_policies p
		JOIN policy_versions v
		  ON v.id = p.current_version_id AND v.organization_id = p.organization_id
		WHERE p.organization_id = $1 AND p.agent_id = $2 AND p.status = 'active' AND p.scope = 'agent'`, organizationID, agentID)
	if err != nil {
		return nil, nil, err
	}
	return organization, agent, nil
}

func (p *Postgres) Record(ctx context.Context, record authz.Record) (authz.Saved, error) {
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		saved, err := p.saveOnce(ctx, record)
		if err == nil {
			return saved, nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "40001" {
			last = err
			continue
		}
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "tool_invocations_idempotency_uq" {
			last = err
			continue
		}
		return authz.Saved{}, err
	}
	if last == nil {
		last = errors.New("audit append failed")
	}
	return authz.Saved{}, last
}

func (p *Postgres) LoadDecision(ctx context.Context, organizationID string, agentID string, decisionID string) (authz.Executable, error) {
	var call authz.Executable
	err := p.db.QueryRow(ctx, `
		SELECT d.id::text, d.organization_id::text, d.agent_id::text, d.outcome,
		       ti.execution_id::text, ti.tool_name, ti.operation, ti.resource, ti.idempotency_key
		FROM authorization_decisions d
		JOIN tool_invocations ti
		  ON ti.id = d.tool_invocation_id AND ti.organization_id = d.organization_id
		WHERE d.id = $1 AND d.organization_id = $2 AND d.agent_id = $3`,
		decisionID, organizationID, agentID).Scan(
		&call.DecisionID, &call.OrganizationID, &call.AgentID, &call.Outcome,
		&call.ExecutionID, &call.ToolName, &call.Operation, &call.Resource, &call.IdempotencyKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Executable{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.Executable{}, err
	}
	return call, nil
}

func (p *Postgres) Finish(ctx context.Context, call authz.Executable, run func() (map[string]any, error)) (authz.ExecuteResult, error) {
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return authz.ExecuteResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status, metadata string
	err = tx.QueryRow(ctx, `
		SELECT status, metadata::text
		FROM executions
		WHERE organization_id = $1 AND id = $2
		FOR UPDATE`, call.OrganizationID, call.ExecutionID).Scan(&status, &metadata)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.ExecuteResult{}, authz.ErrNotFound
	}
	if err != nil {
		return authz.ExecuteResult{}, err
	}
	if status == "completed" {
		result, err := storedResult(metadata)
		if err != nil {
			return authz.ExecuteResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return authz.ExecuteResult{}, err
		}
		result.DecisionID = call.DecisionID
		return result, nil
	}
	prior := "running"
	if call.ApprovalID != "" {
		prior = "awaiting_approval"
		if status != prior {
			return authz.ExecuteResult{}, authz.ErrConflict
		}
		if err := consumeApproval(ctx, tx, call, metadata); err != nil {
			return authz.ExecuteResult{}, err
		}
	} else if status != prior {
		return authz.ExecuteResult{}, authz.ErrConflict
	}
	payload, err := run()
	if err != nil {
		return authz.ExecuteResult{}, err
	}
	envelope := map[string]any{"adapter": adapter.SampleEcho, "result": payload}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return authz.ExecuteResult{}, err
	}
	occurred := time.Now().UTC().Truncate(time.Microsecond)
	tag, err := tx.Exec(ctx, `
		UPDATE executions
		SET status = 'completed', ended_at = $3, metadata = $4::jsonb
		WHERE organization_id = $1 AND id = $2 AND status = $5`,
		call.OrganizationID, call.ExecutionID, occurred, string(encoded), prior)
	if err != nil {
		return authz.ExecuteResult{}, err
	}
	if tag.RowsAffected() != 1 {
		return authz.ExecuteResult{}, authz.ErrConflict
	}
	eventPayload, err := auditchain.Canonical(map[string]any{
		"adapter":     adapter.SampleEcho,
		"decision_id": call.DecisionID,
		"operation":   call.Operation,
		"resource":    call.Resource,
		"tool_name":   call.ToolName,
	})
	if err != nil {
		return authz.ExecuteResult{}, err
	}
	if err := appendAudit(ctx, tx, call.OrganizationID, call.AgentID, call.ExecutionID, "tool.executed", eventPayload, occurred); err != nil {
		return authz.ExecuteResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return authz.ExecuteResult{}, err
	}
	return authz.ExecuteResult{
		DecisionID: call.DecisionID,
		Outcome:    "allow",
		Adapter:    adapter.SampleEcho,
		Result:     payload,
	}, nil
}

func (p *Postgres) saveOnce(ctx context.Context, record authz.Record) (authz.Saved, error) {
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return authz.Saved{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, found, err := readIdempotent(ctx, tx, record)
	if err != nil {
		return authz.Saved{}, err
	}
	if found {
		if err := tx.Commit(ctx); err != nil {
			return authz.Saved{}, err
		}
		return existing, nil
	}

	occurred := time.Now().UTC().Truncate(time.Microsecond)
	status := "completed"
	var endedAt any = occurred
	metadata := []byte(`{}`)
	switch record.Decision.Outcome {
	case policy.OutcomeAllow:
		status = "running"
		endedAt = nil
	case policy.OutcomeRequireApproval:
		status = "awaiting_approval"
		endedAt = nil
		encoded, err := json.Marshal(map[string]string{"payload_hash": record.RawBodyHash})
		if err != nil {
			return authz.Saved{}, err
		}
		metadata = encoded
	}
	var inserted string
	err = tx.QueryRow(ctx, `
		INSERT INTO executions (organization_id, id, agent_id, status, started_at, ended_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
		ON CONFLICT (organization_id, id) DO NOTHING
		RETURNING id::text`,
		record.OrganizationID, record.ExecutionID, record.AgentID, status, occurred, endedAt, string(metadata)).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Saved{}, authz.ErrConflict
	}
	if err != nil {
		return authz.Saved{}, err
	}

	var invocationID string
	err = tx.QueryRow(ctx, `
		INSERT INTO tool_invocations (
			organization_id, execution_id, agent_id, idempotency_key, tool_name, operation,
			resource, arguments_redacted, arguments_hash, requested_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
		RETURNING id::text`,
		record.OrganizationID, record.ExecutionID, record.AgentID, record.IdempotencyKey,
		record.ToolName, record.Operation, record.Resource, string(record.ArgumentsRedacted),
		record.ArgumentsHash, record.RequestedAt).Scan(&invocationID)
	if err != nil {
		return authz.Saved{}, err
	}

	explanation, err := json.Marshal(record.Decision.Explanation)
	if err != nil {
		return authz.Saved{}, err
	}
	var decisionID string
	err = tx.QueryRow(ctx, `
		INSERT INTO authorization_decisions (
			organization_id, tool_invocation_id, agent_id, outcome, policy_id, policy_version_id,
			explanation, risk_level, decided_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
		RETURNING id::text`,
		record.OrganizationID, invocationID, record.AgentID, string(record.Decision.Outcome),
		nullUUID(record.Decision.Explanation.PolicyID), nullUUID(record.Decision.PolicyVersionID),
		string(explanation), record.Risk, occurred).Scan(&decisionID)
	if err != nil {
		return authz.Saved{}, err
	}

	eventPayload, err := eventDocument(record)
	if err != nil {
		return authz.Saved{}, err
	}
	if err := appendAudit(ctx, tx, record.OrganizationID, record.AgentID, record.ExecutionID, "authorization.decided", eventPayload, occurred); err != nil {
		return authz.Saved{}, err
	}

	saved := authz.Saved{
		DecisionID:  decisionID,
		Outcome:     string(record.Decision.Outcome),
		Explanation: record.Decision.Explanation,
	}
	if record.Decision.Outcome == policy.OutcomeRequireApproval {
		err = tx.QueryRow(ctx, `
			INSERT INTO approval_requests (
				organization_id, tool_invocation_id, authorization_decision_id, agent_id,
				payload_hash, expires_at
			) VALUES ($1, $2, $3, $4, $5, now() + interval '15 minutes')
			RETURNING id::text, expires_at`,
			record.OrganizationID, invocationID, decisionID, record.AgentID, record.RawBodyHash).Scan(
			&saved.ApprovalID, &saved.ApprovalExpiresAt)
		if err != nil {
			return authz.Saved{}, err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agents SET last_activity_at = $3
		WHERE id = $1 AND organization_id = $2`, record.AgentID, record.OrganizationID, occurred); err != nil {
		return authz.Saved{}, err
	}
	if err := noteBehavior(ctx, tx, record); err != nil {
		return authz.Saved{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return authz.Saved{}, err
	}
	return saved, nil
}

func (p *Postgres) onePolicy(ctx context.Context, sql string, args ...any) (*policy.Source, error) {
	rows, err := p.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var found *policy.Source
	for rows.Next() {
		if found != nil {
			return nil, errors.New("more than one active policy")
		}
		var source policy.Source
		var document, hash string
		if err := rows.Scan(&source.PolicyID, &source.VersionID, &source.Version, &document, &hash); err != nil {
			return nil, err
		}
		parsed, err := jsondoc.Parse([]byte(document))
		if err != nil {
			return nil, errors.New("policy document rejected")
		}
		canonical, err := auditchain.Canonical(parsed)
		if err != nil {
			return nil, errors.New("policy document rejected")
		}
		sum := sha256.Sum256(canonical)
		if hex.EncodeToString(sum[:]) != hash {
			return nil, errors.New("policy document rejected")
		}
		decoded, err := policy.Parse(canonical)
		if err != nil {
			return nil, errors.New("policy document rejected")
		}
		source.Document = decoded
		found = &source
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return found, nil
}

func readIdempotent(ctx context.Context, tx pgx.Tx, record authz.Record) (authz.Saved, bool, error) {
	var saved authz.Saved
	var tool, operation, resource, argumentsHash, executionID, agentID, explanation string
	var approvalID *string
	var approvalExpires *time.Time
	err := tx.QueryRow(ctx, `
		SELECT ti.agent_id::text, ti.execution_id::text, ti.tool_name, ti.operation, ti.resource, ti.arguments_hash,
		       d.id::text, d.outcome, d.explanation::text, ar.id::text, ar.expires_at
		FROM tool_invocations ti
		JOIN authorization_decisions d
		  ON d.tool_invocation_id = ti.id AND d.organization_id = ti.organization_id
		LEFT JOIN approval_requests ar
		  ON ar.authorization_decision_id = d.id AND ar.organization_id = d.organization_id
		WHERE ti.organization_id = $1 AND ti.idempotency_key = $2
		FOR UPDATE OF ti`, record.OrganizationID, record.IdempotencyKey).Scan(
		&agentID, &executionID, &tool, &operation, &resource, &argumentsHash,
		&saved.DecisionID, &saved.Outcome, &explanation, &approvalID, &approvalExpires)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Saved{}, false, nil
	}
	if err != nil {
		return authz.Saved{}, false, err
	}
	if agentID != record.AgentID || executionID != record.ExecutionID || tool != record.ToolName || operation != record.Operation || resource != record.Resource || argumentsHash != record.ArgumentsHash {
		return authz.Saved{}, false, authz.ErrConflict
	}
	if err := json.Unmarshal([]byte(explanation), &saved.Explanation); err != nil {
		return authz.Saved{}, false, err
	}
	if approvalID != nil {
		saved.ApprovalID = *approvalID
	}
	if approvalExpires != nil {
		saved.ApprovalExpiresAt = *approvalExpires
	}
	return saved, true, nil
}

func noteBehavior(ctx context.Context, tx pgx.Tx, record authz.Record) error {
	if record.ArgumentBytes > limits.ArgumentByteLimit {
		if err := insertIncident(ctx, tx, record, "low", "arguments exceed the behavioral size rule", "oversized_arguments", map[string]any{
			"rule":           "oversized_arguments",
			"argument_bytes": record.ArgumentBytes,
			"execution_id":   record.ExecutionID,
		}); err != nil {
			return err
		}
	}
	if record.Decision.Outcome != policy.OutcomeDeny {
		return nil
	}
	var denies int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM authorization_decisions
		WHERE organization_id = $1 AND agent_id = $2 AND outcome = 'deny'
		  AND decided_at > now() - interval '10 minutes'`,
		record.OrganizationID, record.AgentID).Scan(&denies); err != nil {
		return err
	}
	if denies != limits.DenyBurst {
		return nil
	}
	return insertIncident(ctx, tx, record, "medium", "repeated denies opened a behavioral incident", "deny_burst", map[string]any{
		"rule":         "deny_burst",
		"deny_count":   denies,
		"execution_id": record.ExecutionID,
	})
}

func insertIncident(ctx context.Context, tx pgx.Tx, record authz.Record, severity string, title string, reason string, evidence map[string]any) error {
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO security_incidents (
			organization_id, agent_id, severity, status, title, detection_reason, evidence
		) VALUES ($1, $2, $3, 'open', $4, $5, $6::jsonb)`,
		record.OrganizationID, record.AgentID, severity, title, reason, string(encoded))
	return err
}

func eventDocument(record authz.Record) ([]byte, error) {
	parsed, err := jsondoc.Parse(record.ArgumentsRedacted)
	if err != nil {
		return nil, err
	}
	arguments, ok := parsed.(map[string]any)
	if !ok {
		return nil, errors.New("redacted arguments are not an object")
	}
	return auditchain.Canonical(map[string]any{
		"arguments": arguments,
		"operation": record.Operation,
		"outcome":   string(record.Decision.Outcome),
		"reason":    record.Decision.Explanation.Reason,
		"resource":  record.Resource,
		"tool_name": record.ToolName,
	})
}

func appendAudit(ctx context.Context, tx pgx.Tx, organizationID string, agentID string, executionID string, eventType string, payload []byte, occurred time.Time) error {
	var prev string
	err := tx.QueryRow(ctx, `
		SELECT last_hash FROM audit_chain_heads WHERE organization_id = $1 FOR UPDATE`, organizationID).Scan(&prev)
	if errors.Is(err, pgx.ErrNoRows) {
		prev = auditchain.GenesisPrevHash
	} else if err != nil {
		return err
	}
	eventID, err := idgen.New()
	if err != nil {
		return err
	}
	link, err := auditchain.Hash(prev, auditchain.Event{
		EventID:         eventID,
		OrganizationID:  organizationID,
		EventType:       eventType,
		OccurredAt:      occurred,
		PayloadRedacted: payload,
	})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO security_events (
			id, organization_id, agent_id, execution_id, event_type, payload_redacted, occurred_at
		) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
		eventID, organizationID, agentID, executionID, eventType, string(payload), occurred); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT agentshield_append_audit_link($1, $2, $3, $4)`, organizationID, eventID, link.PrevHash, link.EventHash)
	return err
}

func consumeApproval(ctx context.Context, tx pgx.Tx, call authz.Executable, executionMetadata string) error {
	var bound struct {
		PayloadHash string `json:"payload_hash"`
	}
	if err := json.Unmarshal([]byte(executionMetadata), &bound); err != nil || len(bound.PayloadHash) != 64 {
		return authz.ErrApprovalBinding
	}
	var status, payloadHash, decisionID, agentID string
	var expires time.Time
	err := tx.QueryRow(ctx, `
		SELECT status, payload_hash, authorization_decision_id::text, agent_id::text, expires_at
		FROM approval_requests
		WHERE id = $1 AND organization_id = $2
		FOR UPDATE`, call.ApprovalID, call.OrganizationID).Scan(
		&status, &payloadHash, &decisionID, &agentID, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.ErrNotFound
	}
	if err != nil {
		return err
	}
	if decisionID != call.DecisionID || agentID != call.AgentID || payloadHash != bound.PayloadHash {
		return authz.ErrApprovalBinding
	}
	if (status == "pending" || status == "approved") && !expires.After(time.Now()) {
		return authz.ErrApprovalExpired
	}
	if status == "pending" {
		return authz.ErrApprovalPending
	}
	if status != "approved" {
		return authz.ErrConflict
	}
	tag, err := tx.Exec(ctx, `
		UPDATE approval_requests
		SET status = 'consumed', consumed_at = now()
		WHERE id = $1 AND organization_id = $2 AND status = 'approved' AND consumed_at IS NULL
		  AND decided_by IS NOT NULL AND decided_by <> agent_id`,
		call.ApprovalID, call.OrganizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return authz.ErrApprovalBinding
	}
	return nil
}

func storedResult(metadata string) (authz.ExecuteResult, error) {
	var envelope struct {
		Adapter string         `json:"adapter"`
		Result  map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(metadata), &envelope); err != nil {
		return authz.ExecuteResult{}, err
	}
	if envelope.Adapter != adapter.SampleEcho {
		return authz.ExecuteResult{}, errors.New("stored execution has no sample result")
	}
	return authz.ExecuteResult{Outcome: "allow", Adapter: envelope.Adapter, Result: envelope.Result}, nil
}

func nullUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

type credential struct {
	status    string
	publicKey []byte
	notBefore time.Time
	notAfter  *time.Time
}

func (c credential) active(now time.Time) bool {
	if c.status != "active" || len(c.publicKey) != 32 {
		return false
	}
	if now.Before(c.notBefore) {
		return false
	}
	if c.notAfter != nil && !now.Before(*c.notAfter) {
		return false
	}
	return true
}

func valueOrZero(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}

// Directory, PolicyReader, and Decisions adapt Postgres to the authorization
// interfaces. One Go type cannot expose both Load signatures.
type Directory struct{ DB *Postgres }

func (d Directory) Lookup(ctx context.Context, agentID string) (authz.Principal, error) {
	return d.DB.Lookup(ctx, agentID)
}

type PolicyReader struct{ DB *Postgres }

func (p PolicyReader) Load(ctx context.Context, organizationID string, agentID string) (*policy.Source, *policy.Source, error) {
	return p.DB.Load(ctx, organizationID, agentID)
}

type Decisions struct{ DB *Postgres }

func (d Decisions) Record(ctx context.Context, record authz.Record) (authz.Saved, error) {
	return d.DB.Record(ctx, record)
}

func (d Decisions) Load(ctx context.Context, organizationID string, agentID string, decisionID string) (authz.Executable, error) {
	return d.DB.LoadDecision(ctx, organizationID, agentID, decisionID)
}

func (d Decisions) Finish(ctx context.Context, call authz.Executable, run func() (map[string]any, error)) (authz.ExecuteResult, error) {
	return d.DB.Finish(ctx, call, run)
}
