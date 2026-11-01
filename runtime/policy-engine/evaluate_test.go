package policy

import "testing"

func permissions(allowed, denied, approval []string) Permissions {
	if allowed == nil {
		allowed = []string{}
	}
	if denied == nil {
		denied = []string{}
	}
	if approval == nil {
		approval = []string{}
	}
	return Permissions{Allowed: allowed, Denied: denied, ApprovalRequired: approval}
}

func source(id string, version int, document Document) *Source {
	return &Source{PolicyID: id, VersionID: id + "-version", Version: version, Document: document}
}

func TestEvaluatePrecedence(t *testing.T) {
	org := source("org", 1, Document{Permissions: permissions(
		[]string{"tickets.read", "customer.update"},
		[]string{"database.export"},
		nil,
	)})
	agent := source("agent", 2, Document{Permissions: permissions(
		[]string{"tickets.read", "database.export"},
		nil,
		[]string{"customer.update"},
	)})

	deny, err := Evaluate(org, agent, "database.export", "customers")
	if err != nil || deny.Outcome != OutcomeDeny || deny.Explanation.Reason != "explicit deny" {
		t.Fatalf("cross-document deny = %+v %v", deny, err)
	}
	if deny.Explanation.PolicyID != "org" {
		t.Fatalf("deny policy = %s", deny.Explanation.PolicyID)
	}

	approval, err := Evaluate(org, agent, "customer.update", "customer-1")
	if err != nil || approval.Outcome != OutcomeRequireApproval {
		t.Fatalf("cross-document approval = %+v %v", approval, err)
	}

	allow, err := Evaluate(org, agent, "tickets.read", "ticket-1")
	if err != nil || allow.Outcome != OutcomeAllow || allow.Explanation.PolicyID != "org" {
		t.Fatalf("allow = %+v %v", allow, err)
	}

	unknown, err := Evaluate(org, agent, "payment.refund", "payment-1")
	if err != nil || unknown.Outcome != OutcomeDeny || unknown.Explanation.Reason != "default deny" {
		t.Fatalf("unknown = %+v %v", unknown, err)
	}

	missing, err := Evaluate(nil, nil, "tickets.read", "ticket-1")
	if err != nil || missing.Outcome != OutcomeDeny || missing.Explanation.Reason != "no active policy" {
		t.Fatalf("missing = %+v %v", missing, err)
	}
}

func TestEvaluateResourceRulesOnlyNarrow(t *testing.T) {
	org := source("org", 1, Document{
		Permissions: permissions([]string{"tickets.read"}, nil, nil),
		ResourceRules: []ResourceRule{
			{Effect: "deny", Action: "tickets.read", Resource: "secret"},
			{Effect: "require_approval", Action: "tickets.read", Resource: "billing"},
			{Effect: "allow", Action: "tickets.read", Resource: "public"},
		},
	})

	denied, err := Evaluate(org, nil, "tickets.read", "secret")
	if err != nil || denied.Outcome != OutcomeDeny || denied.Explanation.Reason != "resource denied" {
		t.Fatalf("resource deny = %+v %v", denied, err)
	}
	approval, err := Evaluate(org, nil, "tickets.read", "billing")
	if err != nil || approval.Outcome != OutcomeRequireApproval {
		t.Fatalf("resource approval = %+v %v", approval, err)
	}
	allowed, err := Evaluate(org, nil, "tickets.read", "public")
	if err != nil || allowed.Outcome != OutcomeAllow {
		t.Fatalf("resource allow = %+v %v", allowed, err)
	}
	other, err := Evaluate(org, nil, "tickets.read", "other")
	if err != nil || other.Outcome != OutcomeDeny || other.Explanation.Reason != "resource not permitted" {
		t.Fatalf("unmatched resource = %+v %v", other, err)
	}
}

func TestUnmatchedResourceDenyDoesNotRemoveOtherAllows(t *testing.T) {
	org := source("org", 1, Document{
		Permissions:   permissions([]string{"tickets.read"}, nil, nil),
		ResourceRules: []ResourceRule{{Effect: "deny", Action: "tickets.read", Resource: "secret"}},
	})
	decision, err := Evaluate(org, nil, "tickets.read", "public")
	if err != nil || decision.Outcome != OutcomeAllow {
		t.Fatalf("decision = %+v %v", decision, err)
	}
	if decision.Explanation.Reason != "allowed" {
		t.Fatalf("reason = %s", decision.Explanation.Reason)
	}
}

func TestValidateRejectsOverlapAndGrants(t *testing.T) {
	overlap := Document{Permissions: permissions(
		[]string{"tickets.read"},
		[]string{"tickets.read"},
		nil,
	)}
	if err := Validate(overlap); err == nil {
		t.Fatal("accepted an action in two lists")
	}
	grant := Document{
		Permissions:   permissions(nil, nil, nil),
		ResourceRules: []ResourceRule{{Effect: "allow", Action: "tickets.read", Resource: "ticket-1"}},
	}
	if err := Validate(grant); err == nil {
		t.Fatal("accepted a resource rule that grants a new action")
	}
	override := Document{
		Permissions:   permissions(nil, []string{"tickets.read"}, nil),
		ResourceRules: []ResourceRule{{Effect: "allow", Action: "tickets.read", Resource: "ticket-1"}},
	}
	if err := Validate(override); err == nil {
		t.Fatal("accepted a resource rule on a denied action")
	}
}

func TestEvaluateRejectsInvalidDocument(t *testing.T) {
	org := source("org", 1, Document{Permissions: permissions([]string{"tickets.read"}, []string{"tickets.read"}, nil)})
	_, err := Evaluate(org, nil, "tickets.read", "ticket-1")
	if err == nil {
		t.Fatal("expected validation to fail closed")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte(`{"permissions":{"allowed":[],"denied":[],"approval_required":[]},"private_key":"no"}`))
	if err == nil {
		t.Fatal("accepted an unknown field")
	}
}
