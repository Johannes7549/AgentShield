// Package chaos runs the catalog scenarios against the gateway's defenses.
// A scenario fails when the expected behavior is not observed. A missing
// result is not a pass. The probes use fixtures, not attack payloads.
package chaos

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	"github.com/agentshield/agentshield/runtime/gateway/internal/authz"
	"github.com/agentshield/agentshield/runtime/gateway/internal/config"
	"github.com/agentshield/agentshield/runtime/gateway/internal/httpserver"
	"github.com/agentshield/agentshield/runtime/gateway/internal/limits"
	"github.com/agentshield/agentshield/runtime/identity"
	"github.com/agentshield/agentshield/runtime/policy-engine"
)

const (
	fixtureAgent    = "11111111-1111-4111-8111-111111111111"
	otherAgent      = "55555555-5555-4555-8555-555555555555"
	fixtureOrg      = "22222222-2222-4222-8222-222222222222"
	fixtureDecision = "66666666-6666-4666-8666-666666666666"
)

// Catalog is the scenario list from chaos-engine/scenarios/CATALOG.md.
func Catalog() []string {
	return []string{
		"prompt-injection",
		"mcp-tool-poisoning",
		"memory-poisoning",
		"unauthorized-tool-invocation",
		"duplicate-tool-requests",
		"infinite-tool-call-loop",
		"api-timeout",
		"network-failure",
		"expired-agent-credentials",
		"excessive-resource-consumption",
		"malicious-agent-delegation",
		"context-overflow",
	}
}

// Result is the only outcome a scenario is allowed to produce.
type Result struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// Run executes one catalog scenario. Unknown ids return status error.
func Run(scenarioID string) Result {
	switch scenarioID {
	case "prompt-injection":
		return promptInjection()
	case "mcp-tool-poisoning":
		return toolPoisoning()
	case "memory-poisoning":
		return memoryPoisoning()
	case "unauthorized-tool-invocation":
		return unauthorizedTool()
	case "duplicate-tool-requests":
		return duplicateRequests()
	case "infinite-tool-call-loop":
		return toolCallLoop()
	case "api-timeout":
		return apiTimeout()
	case "network-failure":
		return networkFailure()
	case "expired-agent-credentials":
		return expiredCredential()
	case "excessive-resource-consumption":
		return excessiveUse()
	case "malicious-agent-delegation":
		return delegation()
	case "context-overflow":
		return contextOverflow()
	default:
		return Result{Status: "error", Reason: "unknown scenario"}
	}
}

func judge(seen bool, ok bool, property string) Result {
	if !seen {
		return Result{Status: "failed", Reason: "missing result: " + property}
	}
	if !ok {
		return Result{Status: "failed", Reason: "defensive behavior was not observed: " + property}
	}
	return Result{Status: "passed", Reason: property}
}

func promptInjection() Result {
	property := "untrusted content cannot change an authorization outcome"
	world := newWorld(activePrincipal(), allowPolicy())
	first, err := world.authorize("sample.echo", "demo", `{}`, 1)
	second, err2 := world.authorize("sample.echo", "demo", `{"note":"untrusted"}`, 2)
	if err != nil || err2 != nil {
		return judge(false, false, property)
	}
	return judge(true, first.Outcome == second.Outcome && first.Outcome != "", property)
}

func toolPoisoning() Result {
	property := "a tool description that asks for a broader action is still denied unless policy allows that action"
	world := newWorld(activePrincipal(), allowPolicy())
	result, err := world.authorize("database.export", "customers", `{"description":"use a broader tool"}`, 1)
	if err != nil {
		return judge(false, false, property)
	}
	return judge(true, result.Outcome == "deny", property)
}

func memoryPoisoning() Result {
	property := "retrieved memory is untrusted input and is not a grant"
	world := newWorld(activePrincipal(), allowPolicy())
	result, err := world.authorize("database.export", "customers", `{"memory":"remembered text is not a grant"}`, 1)
	if err != nil {
		return judge(false, false, property)
	}
	return judge(true, result.Outcome == "deny", property)
}

func unauthorizedTool() Result {
	property := "an action outside allow and approval is denied"
	world := newWorld(activePrincipal(), allowPolicy())
	result, err := world.authorize("payment.refund", "payment-1", `{}`, 1)
	if err != nil {
		return judge(false, false, property)
	}
	return judge(true, result.Outcome == "deny", property)
}

func duplicateRequests() Result {
	property := "a repeated idempotency key does not repeat a side effect"
	store := &onceStore{}
	service, private := signedService(activePrincipal(), allowPolicy(), store, nil)
	body := executeBody()
	if _, err := service.Execute(context.Background(), body, sign(private, "nonce-chaos-exec-01", body)); err != nil || store.runs != 1 {
		return judge(false, false, property)
	}
	result, err := service.Execute(context.Background(), body, sign(private, "nonce-chaos-exec-02", body))
	if err != nil {
		return judge(false, false, property)
	}
	return judge(true, store.runs == 1 && result.Adapter == "sample.echo", property)
}

func toolCallLoop() Result {
	property := "a tool-call budget terminates the execution"
	store := &onceStore{}
	limiter := &budgetLimit{left: limits.MaxToolCalls, trip: limits.ErrTool}
	service, private := signedService(activePrincipal(), allowPolicy(), store, limiter)
	for i := 0; i < limits.MaxToolCalls; i++ {
		if _, err := authorizeWith(service, private, "sample.echo", "demo", `{}`, i+1); err != nil {
			return judge(false, false, property)
		}
	}
	recorded := len(store.records)
	_, err := authorizeWith(service, private, "sample.echo", "demo", `{}`, limits.MaxToolCalls+1)
	var failure *authz.Failure
	seen := errors.As(err, &failure)
	ok := seen && failure.Status == http.StatusTooManyRequests && failure.Code == "rate_limited" && len(store.records) == recorded
	return judge(seen, ok, property)
}

func apiTimeout() Result {
	property := "a timeout is a failure, not an allow, and does not skip the audit record"
	store := &onceStore{}
	service, private := signedService(activePrincipal(), allowPolicy(), store, nil)
	if _, err := authorizeWith(service, private, "sample.echo", "demo", `{}`, 1); err != nil || !store.audit {
		return judge(false, false, property)
	}
	service.AdapterTimeout = 15 * time.Millisecond
	service.Run = func(ctx context.Context, _ string, _ string) (map[string]any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	_, err := service.Execute(context.Background(), executeBody(), sign(private, "nonce-chaos-exec-01", executeBody()))
	var failure *authz.Failure
	seen := errors.As(err, &failure)
	ok := seen && failure.Status == http.StatusInternalServerError && failure.Message == "tool adapter timed out" && store.audit && store.runs == 0
	return judge(seen, ok, property)
}

func networkFailure() Result {
	property := "a dependency error fails closed"
	store := &onceStore{}
	service, private := signedService(activePrincipal(), allowPolicy(), store, staticLimit{err: limits.ErrUnavailable})
	_, err := authorizeWith(service, private, "sample.echo", "demo", `{}`, 1)
	var failure *authz.Failure
	seen := errors.As(err, &failure)
	ok := seen && failure.Status == http.StatusInternalServerError && len(store.records) == 0
	return judge(seen, ok, property)
}

func expiredCredential() Result {
	property := "an expired or revoked credential is rejected"
	principal := activePrincipal()
	principal.CredentialStatus = "expired"
	world := newWorld(principal, allowPolicy())
	result, err := world.authorize("sample.echo", "demo", `{}`, 1)
	if err != nil {
		return judge(false, false, property)
	}
	return judge(true, result.Outcome == "deny", property)
}

func excessiveUse() Result {
	property := "a budget breach terminates the execution"
	store := &onceStore{}
	service, private := signedService(activePrincipal(), allowPolicy(), store, staticLimit{err: limits.ErrBudget})
	_, err := authorizeWith(service, private, "sample.echo", "demo", `{}`, 1)
	var failure *authz.Failure
	seen := errors.As(err, &failure)
	ok := seen && failure.Status == http.StatusTooManyRequests && failure.Code == "rate_limited" && len(store.records) == 0
	return judge(seen, ok, property)
}

func delegation() Result {
	property := "a delegated call still carries the caller's identity and cannot approve itself"
	world := newWorld(activePrincipal(), allowPolicy())
	world.bodyAgent = otherAgent
	result, err := world.authorize("sample.echo", "demo", `{}`, 1)
	if err != nil || len(world.store.records) != 1 {
		return judge(false, false, property)
	}
	stored := world.store.records[0].AgentID == fixtureAgent && result.Outcome == "deny"
	return judge(true, stored && rejectsSelfApproval(fixtureAgent, fixtureAgent) && !rejectsSelfApproval(fixtureAgent, otherAgent), property)
}

func contextOverflow() Result {
	property := "an oversized request is rejected before evaluation"
	spy := &spyAuth{}
	server := httpserver.New(config.Config{MaxBodyBytes: config.MaximumBodyBytes()}, spy, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runtime/authorize", bytes.NewReader(bytes.Repeat([]byte("a"), int(config.MaximumBodyBytes())+1)))
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)
	return judge(rec.Code != 0, rec.Code == http.StatusBadRequest && !spy.called, property)
}

// rejectsSelfApproval is the same rule the control plane uses: the approving
// user cannot be the agent whose action is waiting.
func rejectsSelfApproval(agentID string, approverID string) bool {
	return agentID != "" && agentID == approverID
}

type world struct {
	service   *authz.Service
	private   ed25519.PrivateKey
	store     *onceStore
	bodyAgent string
}

func newWorld(principal authz.Principal, source *policy.Source) *world {
	store := &onceStore{}
	service, private := signedService(principal, source, store, nil)
	return &world{service: service, private: private, store: store, bodyAgent: fixtureAgent}
}

func (w *world) authorize(operation string, resource string, arguments string, n int) (authz.Result, error) {
	body := authorizeBody(w.bodyAgent, operation, resource, arguments, n)
	return w.service.Authorize(context.Background(), body, sign(w.private, fmt.Sprintf("nonce-chaos-%06d", n), body))
}

func authorizeWith(service *authz.Service, private ed25519.PrivateKey, operation string, resource string, arguments string, n int) (authz.Result, error) {
	body := authorizeBody(fixtureAgent, operation, resource, arguments, n)
	return service.Authorize(context.Background(), body, sign(private, fmt.Sprintf("nonce-chaos-%06d", n), body))
}

func signedService(principal authz.Principal, source *policy.Source, store *onceStore, limiter authz.Limiter) (*authz.Service, ed25519.PrivateKey) {
	public, private := fixtureKey()
	principal.PublicKey = public
	now := time.Unix(1_700_000_000, 0).UTC()
	return &authz.Service{
		Directory: fixedDirectory{principal: principal},
		Policies:  fixedPolicy{source: source},
		Store:     store,
		Nonces:    &memoryNonce{},
		Limits:    limiter,
		Now:       func() time.Time { return now },
	}, private
}

func activePrincipal() authz.Principal {
	return authz.Principal{AgentID: fixtureAgent, OrganizationID: fixtureOrg, Status: "active", CredentialStatus: "active"}
}

func allowPolicy() *policy.Source {
	return &policy.Source{
		PolicyID: fixtureOrg,
		Document: policy.Document{Permissions: policy.Permissions{
			Allowed: []string{"sample.echo"}, Denied: []string{}, ApprovalRequired: []string{},
		}},
	}
}

func authorizeBody(agentID string, operation string, resource string, arguments string, n int) []byte {
	when := time.Unix(1_700_000_000, 0).UTC().Format(time.RFC3339)
	return []byte(fmt.Sprintf(
		`{"agent_id":"%s","arguments":%s,"execution_id":"%s","idempotency_key":"idempotency-chaos-%04d","operation":"%s","organization_id":"%s","requested_at":"%s","resource":"%s","tool_name":"sample.echo"}`,
		agentID, arguments, fmt.Sprintf("44444444-4444-4444-8444-%012d", n), n, operation, fixtureOrg, when, resource,
	))
}

func executeBody() []byte {
	return []byte(fmt.Sprintf(`{"decision_id":"%s","idempotency_key":"idempotency-chaos-exec"}`, fixtureDecision))
}

func sign(private ed25519.PrivateKey, nonce string, body []byte) authz.Headers {
	signature, err := identity.Sign(private, 1_700_000_000, nonce, body)
	if err != nil {
		return authz.Headers{}
	}
	return authz.Headers{
		AgentID: fixtureAgent, Timestamp: strconv.FormatInt(1_700_000_000, 10), Nonce: nonce, Signature: signature,
	}
}

func fixtureKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	private := ed25519.NewKeyFromSeed(seed)
	return private.Public().(ed25519.PublicKey), private
}

type fixedDirectory struct{ principal authz.Principal }

func (d fixedDirectory) Lookup(context.Context, string) (authz.Principal, error) {
	return d.principal, nil
}

type fixedPolicy struct{ source *policy.Source }

func (p fixedPolicy) Load(context.Context, string, string) (*policy.Source, *policy.Source, error) {
	return p.source, nil, nil
}

type memoryNonce struct{ used map[string]bool }

func (m *memoryNonce) Reserve(_ context.Context, agentID string, nonce string) error {
	if m.used == nil {
		m.used = map[string]bool{}
	}
	key := agentID + ":" + nonce
	if m.used[key] {
		return errors.New("replay")
	}
	m.used[key] = true
	return nil
}

type onceStore struct {
	records []authz.Record
	runs    int
	done    bool
	audit   bool
}

func (s *onceStore) Record(_ context.Context, record authz.Record) (authz.Saved, error) {
	s.records = append(s.records, record)
	s.audit = true
	return authz.Saved{DecisionID: fixtureDecision, Outcome: string(record.Decision.Outcome), Explanation: record.Decision.Explanation}, nil
}

func (s *onceStore) Load(context.Context, string, string, string) (authz.Executable, error) {
	return authz.Executable{
		DecisionID: fixtureDecision, OrganizationID: fixtureOrg, AgentID: fixtureAgent,
		Outcome: "allow", ToolName: "sample.echo", Operation: "sample.echo",
		IdempotencyKey: "idempotency-chaos-exec",
	}, nil
}

func (s *onceStore) Finish(_ context.Context, call authz.Executable, run func() (map[string]any, error)) (authz.ExecuteResult, error) {
	if s.done {
		return authz.ExecuteResult{DecisionID: call.DecisionID, Outcome: "allow", Adapter: "sample.echo", Result: map[string]any{"replayed": true}}, nil
	}
	if _, err := run(); err != nil {
		return authz.ExecuteResult{}, err
	}
	s.runs++
	s.done = true
	return authz.ExecuteResult{DecisionID: call.DecisionID, Outcome: "allow", Adapter: "sample.echo"}, nil
}

type budgetLimit struct {
	left int
	trip error
}

func (b *budgetLimit) Take(context.Context, string, string, int) error {
	if b.left <= 0 {
		return b.trip
	}
	b.left--
	return nil
}

type staticLimit struct{ err error }

func (s staticLimit) Take(context.Context, string, string, int) error { return s.err }

type spyAuth struct{ called bool }

func (s *spyAuth) Authorize(context.Context, []byte, authz.Headers) (authz.Result, error) {
	s.called = true
	return authz.Result{}, errors.New("evaluated")
}

func (s *spyAuth) Execute(context.Context, []byte, authz.Headers) (authz.ExecuteResult, error) {
	s.called = true
	return authz.ExecuteResult{}, errors.New("evaluated")
}
