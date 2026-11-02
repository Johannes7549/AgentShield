// Package authz authenticates an agent request and asks the policy library
// for a decision. It does not trust organization ids, permissions, or prior
// approval claims in the body.
package authz

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/agentshield/agentshield/runtime/gateway/internal/adapter"
	"github.com/agentshield/agentshield/runtime/gateway/internal/auditchain"
	"github.com/agentshield/agentshield/runtime/gateway/internal/jsondoc"
	"github.com/agentshield/agentshield/runtime/gateway/internal/limits"
	"github.com/agentshield/agentshield/runtime/gateway/internal/nonce"
	"github.com/agentshield/agentshield/runtime/gateway/internal/redact"
	"github.com/agentshield/agentshield/runtime/identity"
	"github.com/agentshield/agentshield/runtime/policy-engine"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrConflict        = errors.New("conflict")
	ErrApprovalPending = errors.New("approval pending")
	ErrApprovalExpired = errors.New("approval expired")
	ErrApprovalBinding = errors.New("approval binding")

	uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	toolPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
)

type Failure struct {
	Status  int
	Code    string
	Message string
}

func (f *Failure) Error() string { return f.Message }

type Headers struct {
	AgentID       string
	Timestamp     string
	Nonce         string
	Signature     string
	Authorization string
}

type Principal struct {
	AgentID          string
	OrganizationID   string
	Status           string
	CredentialStatus string
	PublicKey        ed25519.PublicKey
}

type Directory interface {
	Lookup(ctx context.Context, agentID string) (Principal, error)
}

type PolicyLoader interface {
	Load(ctx context.Context, organizationID string, agentID string) (organization *policy.Source, agent *policy.Source, err error)
}

type Record struct {
	OrganizationID    string
	AgentID           string
	ExecutionID       string
	IdempotencyKey    string
	ToolName          string
	Operation         string
	Resource          string
	ArgumentsHash     string
	ArgumentsRedacted json.RawMessage
	ArgumentBytes     int
	RequestedAt       time.Time
	Decision          policy.Decision
	RawBodyHash       string
	Risk              string
}

type Saved struct {
	DecisionID        string
	Outcome           string
	Explanation       policy.Explanation
	ApprovalID        string
	ApprovalExpiresAt time.Time
}

type Executable struct {
	DecisionID     string
	OrganizationID string
	AgentID        string
	ExecutionID    string
	Outcome        string
	ToolName       string
	Operation      string
	Resource       string
	IdempotencyKey string
	ApprovalID     string
}

type Store interface {
	Record(ctx context.Context, record Record) (Saved, error)
	Load(ctx context.Context, organizationID string, agentID string, decisionID string) (Executable, error)
	Finish(ctx context.Context, call Executable, run func() (map[string]any, error)) (ExecuteResult, error)
}

type Nonces interface {
	Reserve(ctx context.Context, agentID string, nonce string) error
}

type Limiter interface {
	Take(ctx context.Context, agentID string, tool string, tokens int) error
}

type Circuit interface {
	Allow(ctx context.Context, organizationID string, tool string) error
	Failure(ctx context.Context, organizationID string, tool string) error
	Success(ctx context.Context, organizationID string, tool string) error
}

type ToolRunner func(ctx context.Context, operation string, resource string) (map[string]any, error)

type Result struct {
	DecisionID        string             `json:"decision_id"`
	Outcome           string             `json:"outcome"`
	Explanation       policy.Explanation `json:"explanation"`
	ApprovalID        string             `json:"approval_id,omitempty"`
	ApprovalExpiresAt *time.Time         `json:"approval_expires_at,omitempty"`
}

type ExecuteResult struct {
	DecisionID string         `json:"decision_id"`
	Outcome    string         `json:"outcome"`
	Adapter    string         `json:"adapter"`
	Result     map[string]any `json:"result,omitempty"`
}

type Service struct {
	Directory      Directory
	Policies       PolicyLoader
	Store          Store
	Nonces         Nonces
	Limits         Limiter
	Breaker        Circuit
	Run            ToolRunner
	AdapterTimeout time.Duration
	Now            func() time.Time
}

func (s *Service) Authorize(ctx context.Context, body []byte, headers Headers) (Result, error) {
	principal, err := s.open(ctx, body, headers)
	if err != nil {
		return Result{}, err
	}
	decoded, err := decodeAuthorize(body)
	if err != nil {
		return Result{}, err
	}
	if err := s.takeLimit(ctx, principal.AgentID, decoded.ToolName, len(body)); err != nil {
		return Result{}, err
	}
	if decoded.AgentID != principal.AgentID {
		return s.record(ctx, principal, decoded, body, policy.Deny("body agent_id does not match the authenticated agent"))
	}
	if reason := inactiveReason(principal); reason != "" {
		return s.record(ctx, principal, decoded, body, policy.Deny(reason))
	}
	if decoded.OrganizationID != principal.OrganizationID {
		return s.record(ctx, principal, decoded, body, policy.Deny("organization claim does not match the authenticated agent"))
	}

	organization, agent, err := s.Policies.Load(ctx, principal.OrganizationID, principal.AgentID)
	if err != nil {
		return s.record(ctx, principal, decoded, body, policy.Deny("policy load failed"))
	}
	decision, err := policy.Evaluate(organization, agent, decoded.Operation, decoded.Resource)
	if err != nil {
		return s.record(ctx, principal, decoded, body, policy.Deny("policy evaluation failed"))
	}
	return s.record(ctx, principal, decoded, body, decision)
}

func (s *Service) Execute(ctx context.Context, body []byte, headers Headers) (ExecuteResult, error) {
	principal, err := s.open(ctx, body, headers)
	if err != nil {
		return ExecuteResult{}, err
	}
	decoded, err := decodeExecute(body)
	if err != nil {
		return ExecuteResult{}, err
	}
	if reason := inactiveReason(principal); reason != "" {
		return ExecuteResult{}, fail(http.StatusForbidden, "forbidden", reason)
	}
	call, err := s.Store.Load(ctx, principal.OrganizationID, principal.AgentID, decoded.DecisionID)
	if errors.Is(err, ErrNotFound) {
		return ExecuteResult{}, fail(http.StatusNotFound, "not_found", "decision not found")
	}
	if err != nil {
		return ExecuteResult{}, fail(http.StatusInternalServerError, "internal_error", "internal error")
	}
	if call.IdempotencyKey != decoded.IdempotencyKey {
		return ExecuteResult{}, fail(http.StatusConflict, "conflict", "idempotency key does not match the decision")
	}
	switch policy.Outcome(call.Outcome) {
	case policy.OutcomeDeny:
		return ExecuteResult{}, fail(http.StatusForbidden, "forbidden", "decision is deny")
	case policy.OutcomeRequireApproval:
		if decoded.ApprovalID == "" {
			return ExecuteResult{}, fail(http.StatusConflict, "approval_required", "decision requires approval")
		}
		call.ApprovalID = decoded.ApprovalID
	case policy.OutcomeAllow:
		if decoded.ApprovalID != "" {
			return ExecuteResult{}, fail(http.StatusConflict, "conflict", "approval does not apply to this decision")
		}
	default:
		return ExecuteResult{}, fail(http.StatusInternalServerError, "internal_error", "internal error")
	}
	if call.ToolName != adapter.SampleEcho || call.Operation != adapter.SampleEcho {
		return ExecuteResult{}, fail(http.StatusNotImplemented, "not_implemented", "no adapter is registered for this tool")
	}
	result, err := s.Store.Finish(ctx, call, func() (map[string]any, error) {
		return s.invoke(ctx, call)
	})
	if errors.Is(err, ErrApprovalPending) {
		return ExecuteResult{}, fail(http.StatusConflict, "approval_required", "decision requires approval")
	}
	if errors.Is(err, ErrApprovalExpired) {
		return ExecuteResult{}, fail(http.StatusConflict, "approval_expired", "approval has expired")
	}
	if errors.Is(err, ErrApprovalBinding) {
		return ExecuteResult{}, fail(http.StatusConflict, "conflict", "approval does not match this decision")
	}
	if errors.Is(err, ErrConflict) {
		return ExecuteResult{}, fail(http.StatusConflict, "conflict", "execution cannot be completed")
	}
	if errors.Is(err, limits.ErrOpen) {
		return ExecuteResult{}, fail(http.StatusServiceUnavailable, "circuit_open", "tool circuit is open")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ExecuteResult{}, fail(http.StatusInternalServerError, "internal_error", "tool adapter timed out")
	}
	if err != nil {
		return ExecuteResult{}, fail(http.StatusInternalServerError, "internal_error", "internal error")
	}
	return result, nil
}

func (s *Service) record(ctx context.Context, principal Principal, request *authorizeRequest, body []byte, decision policy.Decision) (Result, error) {
	parsed, err := jsondoc.Parse(request.Arguments)
	if err != nil {
		return Result{}, fail(http.StatusBadRequest, "validation_failed", "arguments are invalid")
	}
	arguments, ok := parsed.(map[string]any)
	if !ok {
		return Result{}, fail(http.StatusBadRequest, "validation_failed", "arguments must be an object")
	}
	canonical, err := auditchain.Canonical(arguments)
	if err != nil {
		return Result{}, fail(http.StatusBadRequest, "validation_failed", "arguments are invalid")
	}
	sum := sha256.Sum256(canonical)
	redacted, err := redact.JSON(canonical)
	if err != nil {
		return Result{}, fail(http.StatusBadRequest, "validation_failed", "arguments are invalid")
	}
	requestedAt, err := time.Parse(time.RFC3339, request.RequestedAt)
	if err != nil {
		return Result{}, fail(http.StatusBadRequest, "validation_failed", "requested_at is invalid")
	}
	bodySum := sha256.Sum256(body)
	saved, err := s.Store.Record(ctx, Record{
		OrganizationID:    principal.OrganizationID,
		AgentID:           principal.AgentID,
		ExecutionID:       request.ExecutionID,
		IdempotencyKey:    request.IdempotencyKey,
		ToolName:          request.ToolName,
		Operation:         request.Operation,
		Resource:          request.Resource,
		ArgumentsHash:     hex.EncodeToString(sum[:]),
		ArgumentsRedacted: redacted,
		ArgumentBytes:     len(canonical),
		RequestedAt:       requestedAt.UTC(),
		Decision:          decision,
		RawBodyHash:       hex.EncodeToString(bodySum[:]),
		Risk:              risk(decision.Outcome),
	})
	if errors.Is(err, ErrConflict) {
		return Result{}, fail(http.StatusConflict, "conflict", "idempotency key does not match this request")
	}
	if err != nil {
		return Result{}, fail(http.StatusInternalServerError, "internal_error", "internal error")
	}
	result := Result{
		DecisionID:  saved.DecisionID,
		Outcome:     saved.Outcome,
		Explanation: saved.Explanation,
	}
	if saved.ApprovalID != "" {
		expires := saved.ApprovalExpiresAt.UTC()
		result.ApprovalID = saved.ApprovalID
		result.ApprovalExpiresAt = &expires
	}
	return result, nil
}

func (s *Service) open(ctx context.Context, body []byte, headers Headers) (Principal, error) {
	if headers.Authorization != "" {
		return Principal{}, fail(http.StatusUnauthorized, "unauthenticated", "human sessions are not accepted by the gateway")
	}
	if len(body) == 0 {
		return Principal{}, fail(http.StatusBadRequest, "validation_failed", "request body is required")
	}
	if _, err := jsondoc.Parse(body); err != nil {
		return Principal{}, fail(http.StatusBadRequest, "validation_failed", "request body is invalid")
	}
	if headers.AgentID == "" || headers.Timestamp == "" || headers.Nonce == "" || headers.Signature == "" {
		return Principal{}, fail(http.StatusUnauthorized, "unauthenticated", "agent signature headers are required")
	}
	if !uuidPattern.MatchString(headers.AgentID) {
		return Principal{}, fail(http.StatusUnauthorized, "unauthenticated", "authentication failed")
	}
	timestamp, err := strconv.ParseInt(headers.Timestamp, 10, 64)
	if err != nil {
		return Principal{}, fail(http.StatusUnauthorized, "unauthenticated", "authentication failed")
	}
	principal, err := s.Directory.Lookup(ctx, headers.AgentID)
	if errors.Is(err, ErrNotFound) {
		return Principal{}, fail(http.StatusUnauthorized, "unauthenticated", "authentication failed")
	}
	if err != nil {
		return Principal{}, fail(http.StatusInternalServerError, "internal_error", "internal error")
	}
	if err := identity.Verify(principal.PublicKey, timestamp, headers.Nonce, body, headers.Signature, s.now()); err != nil {
		return Principal{}, fail(http.StatusUnauthorized, "unauthenticated", "authentication failed")
	}
	if err := s.Nonces.Reserve(ctx, principal.AgentID, headers.Nonce); err != nil {
		if errors.Is(err, nonce.ErrReplay) {
			return Principal{}, fail(http.StatusUnauthorized, "unauthenticated", "nonce already used")
		}
		return Principal{}, fail(http.StatusInternalServerError, "internal_error", "internal error")
	}
	return principal, nil
}

func (s *Service) takeLimit(ctx context.Context, agentID string, tool string, bodyLength int) error {
	if s.Limits == nil {
		return nil
	}
	err := s.Limits.Take(ctx, agentID, tool, limits.Tokens(bodyLength))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, limits.ErrRequests), errors.Is(err, limits.ErrTool), errors.Is(err, limits.ErrBudget):
		return fail(http.StatusTooManyRequests, "rate_limited", err.Error())
	default:
		return fail(http.StatusInternalServerError, "internal_error", "internal error")
	}
}

func (s *Service) adapterTimeout() time.Duration {
	if s.AdapterTimeout > 0 {
		return s.AdapterTimeout
	}
	return limits.AdapterTimeout
}

func (s *Service) invoke(ctx context.Context, call Executable) (map[string]any, error) {
	if s.Breaker != nil {
		if err := s.Breaker.Allow(ctx, call.OrganizationID, call.ToolName); err != nil {
			return nil, err
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, s.adapterTimeout())
	defer cancel()
	run := s.Run
	if run == nil {
		run = echoAdapter
	}
	payload, err := run(runCtx, call.Operation, call.Resource)
	if err != nil {
		if s.Breaker != nil && !errors.Is(err, limits.ErrOpen) && !errors.Is(err, limits.ErrUnavailable) {
			if ferr := s.Breaker.Failure(ctx, call.OrganizationID, call.ToolName); ferr != nil {
				return nil, ferr
			}
		}
		return nil, err
	}
	if s.Breaker != nil {
		if err := s.Breaker.Success(ctx, call.OrganizationID, call.ToolName); err != nil {
			return nil, err
		}
	}
	return payload, nil
}

func echoAdapter(ctx context.Context, operation string, resource string) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	echo, ok := adapter.Echo(operation, resource)
	if !ok {
		return nil, errors.New("sample adapter rejected the operation")
	}
	encoded, err := json.Marshal(echo)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func inactiveReason(principal Principal) string {
	switch principal.Status {
	case "suspended":
		return "agent is suspended"
	case "revoked":
		return "agent is revoked"
	}
	if principal.Status != "active" || principal.CredentialStatus != "active" {
		return "agent credential is not active"
	}
	return ""
}

func risk(outcome policy.Outcome) string {
	switch outcome {
	case policy.OutcomeAllow:
		return "none"
	case policy.OutcomeRequireApproval:
		return "medium"
	default:
		return "low"
	}
}

func fail(status int, code string, message string) *Failure {
	return &Failure{Status: status, Code: code, Message: message}
}

type authorizeRequest struct {
	AgentID        string          `json:"agent_id"`
	OrganizationID string          `json:"organization_id"`
	ExecutionID    string          `json:"execution_id"`
	ToolName       string          `json:"tool_name"`
	Operation      string          `json:"operation"`
	Resource       string          `json:"resource"`
	Arguments      json.RawMessage `json:"arguments"`
	RequestedAt    string          `json:"requested_at"`
	IdempotencyKey string          `json:"idempotency_key"`
}

type executeRequest struct {
	DecisionID     string `json:"decision_id"`
	IdempotencyKey string `json:"idempotency_key"`
	ApprovalID     string `json:"approval_id"`
}

func decodeAuthorize(body []byte) (*authorizeRequest, error) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var request authorizeRequest
	if err := dec.Decode(&request); err != nil || dec.More() {
		return nil, fail(http.StatusBadRequest, "validation_failed", "request body is invalid")
	}
	if !uuidPattern.MatchString(request.AgentID) || !uuidPattern.MatchString(request.OrganizationID) || !uuidPattern.MatchString(request.ExecutionID) {
		return nil, fail(http.StatusBadRequest, "validation_failed", "request body is invalid")
	}
	if !toolPattern.MatchString(request.ToolName) || request.Operation == "" || len(request.Operation) > 128 {
		return nil, fail(http.StatusBadRequest, "validation_failed", "request body is invalid")
	}
	if request.Resource == "" || len(request.Resource) > 512 || strings.ContainsRune(request.Resource, '\x00') {
		return nil, fail(http.StatusBadRequest, "validation_failed", "request body is invalid")
	}
	if len(request.IdempotencyKey) < 16 || len(request.IdempotencyKey) > 200 || !printable(request.IdempotencyKey) {
		return nil, fail(http.StatusBadRequest, "validation_failed", "request body is invalid")
	}
	if len(request.Arguments) == 0 {
		return nil, fail(http.StatusBadRequest, "validation_failed", "arguments must be an object")
	}
	return &request, nil
}

func decodeExecute(body []byte) (*executeRequest, error) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var request executeRequest
	if err := dec.Decode(&request); err != nil || dec.More() {
		return nil, fail(http.StatusBadRequest, "validation_failed", "request body is invalid")
	}
	if !uuidPattern.MatchString(request.DecisionID) {
		return nil, fail(http.StatusBadRequest, "validation_failed", "request body is invalid")
	}
	if request.ApprovalID != "" && !uuidPattern.MatchString(request.ApprovalID) {
		return nil, fail(http.StatusBadRequest, "validation_failed", "request body is invalid")
	}
	if len(request.IdempotencyKey) < 16 || len(request.IdempotencyKey) > 200 || !printable(request.IdempotencyKey) {
		return nil, fail(http.StatusBadRequest, "validation_failed", "request body is invalid")
	}
	return &request, nil
}

func printable(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
