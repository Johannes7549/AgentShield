// Package policy defines the authorization decision contract and the
// deterministic evaluator. Storage, clocks, and network access stay outside
// this package. A caller that receives an error must not execute the tool.
package policy

import "fmt"

type Outcome string

const (
	OutcomeAllow           Outcome = "allow"
	OutcomeDeny            Outcome = "deny"
	OutcomeRequireApproval Outcome = "require_approval"
)

type Explanation struct {
	PolicyID    string `json:"policy_id,omitempty"`
	Version     int    `json:"policy_version,omitempty"`
	MatchedRule string `json:"matched_rule,omitempty"`
	Reason      string `json:"reason"`
}

type Decision struct {
	Outcome         Outcome     `json:"outcome"`
	Explanation     Explanation `json:"explanation"`
	PolicyVersionID string      `json:"-"`
}

// ParseOutcome accepts only the three gateway outcomes. Comparison is case sensitive.
func ParseOutcome(value string) (Outcome, error) {
	switch Outcome(value) {
	case OutcomeAllow, OutcomeDeny, OutcomeRequireApproval:
		return Outcome(value), nil
	default:
		return "", fmt.Errorf("unknown authorization outcome %q", value)
	}
}

// Deny builds a fail-closed decision. It is not an evaluator.
func Deny(reason string) Decision {
	return Decision{
		Outcome:     OutcomeDeny,
		Explanation: Explanation{Reason: reason},
	}
}
