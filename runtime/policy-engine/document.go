package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// ActionPattern is the only action syntax the evaluator accepts.
// Resource comparison is exact. A trailing wildcard is not special.
var ActionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

type Document struct {
	Agent         *AgentName     `json:"agent,omitempty"`
	Permissions   Permissions    `json:"permissions"`
	ResourceRules []ResourceRule `json:"resource_rules,omitempty"`
}

type AgentName struct {
	ID string `json:"id"`
}

type Permissions struct {
	Allowed          []string `json:"allowed"`
	Denied           []string `json:"denied"`
	ApprovalRequired []string `json:"approval_required"`
}

type ResourceRule struct {
	Effect   string `json:"effect"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// Source is one active policy version. The evaluator does not load it.
type Source struct {
	PolicyID  string
	VersionID string
	Version   int
	Document  Document
}

// Parse decodes a policy document and rejects unknown fields.
func Parse(raw []byte) (Document, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var document Document
	if err := dec.Decode(&document); err != nil {
		return Document{}, errors.New("policy document is invalid")
	}
	if dec.More() {
		return Document{}, errors.New("policy document is invalid")
	}
	if err := Validate(document); err != nil {
		return Document{}, err
	}
	return document, nil
}

// Validate applies the document rules from ADR 0004.
// Resource rules may only narrow an action that this document allows.
// They cannot override a deny or an approval list entry.
func Validate(document Document) error {
	if document.Agent != nil {
		if document.Agent.ID == "" || len(document.Agent.ID) > 128 {
			return errors.New("policy agent id is invalid")
		}
	}
	if document.Permissions.Allowed == nil || document.Permissions.Denied == nil || document.Permissions.ApprovalRequired == nil {
		return errors.New("policy permission lists are required")
	}
	seen := map[string]string{}
	lists := []struct {
		name    string
		actions []string
	}{
		{"allowed", document.Permissions.Allowed},
		{"denied", document.Permissions.Denied},
		{"approval_required", document.Permissions.ApprovalRequired},
	}
	for _, list := range lists {
		for _, action := range list.actions {
			if !ActionPattern.MatchString(action) || len(action) > 128 {
				return fmt.Errorf("policy action %q is invalid", action)
			}
			if previous, ok := seen[action]; ok {
				return fmt.Errorf("action %q is in both %s and %s", action, previous, list.name)
			}
			seen[action] = list.name
		}
	}
	for _, rule := range document.ResourceRules {
		switch rule.Effect {
		case string(OutcomeAllow), string(OutcomeDeny), string(OutcomeRequireApproval):
		default:
			return errors.New("resource rule effect is invalid")
		}
		if !ActionPattern.MatchString(rule.Action) {
			return errors.New("resource rule action is invalid")
		}
		if seen[rule.Action] != "allowed" {
			return fmt.Errorf("resource rule for %q does not narrow an allow", rule.Action)
		}
		if rule.Resource == "" || len(rule.Resource) > 512 {
			return errors.New("resource rule resource is invalid")
		}
	}
	return nil
}
