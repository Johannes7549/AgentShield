package policy

// Evaluate applies ADR 0004 to the active organization document and the
// active agent document. Either source may be nil.
//
// Resource rules select among actions that are already allowed. A matching
// resource deny or approval narrows that allow. If any resource rule names
// the action, a request resource that matches none of them is denied. A
// resource rule cannot grant an action that no allow list contains, and it
// cannot remove a list deny or a list approval.
func Evaluate(organization *Source, agent *Source, action string, resource string) (Decision, error) {
	sources := []*Source{organization, agent}
	for _, source := range sources {
		if source == nil {
			continue
		}
		if err := Validate(source.Document); err != nil {
			return Decision{}, err
		}
	}
	if !ActionPattern.MatchString(action) {
		return Deny("operation is not a policy action"), nil
	}

	for _, source := range sources {
		if source != nil && contains(source.Document.Permissions.Denied, action) {
			return fromSource(OutcomeDeny, source, "denied:"+action, "explicit deny"), nil
		}
	}
	for _, source := range sources {
		if source != nil && contains(source.Document.Permissions.ApprovalRequired, action) {
			return fromSource(OutcomeRequireApproval, source, "approval_required:"+action, "approval required"), nil
		}
	}

	var allowSource *Source
	for _, source := range sources {
		if source != nil && contains(source.Document.Permissions.Allowed, action) {
			allowSource = source
			break
		}
	}
	if allowSource == nil {
		if organization == nil && agent == nil {
			return Deny("no active policy"), nil
		}
		return Deny("default deny"), nil
	}

	var matched []scopedRule
	allowRules := 0
	for _, source := range sources {
		if source == nil {
			continue
		}
		for _, rule := range source.Document.ResourceRules {
			if rule.Action != action {
				continue
			}
			if rule.Effect == string(OutcomeAllow) {
				allowRules++
			}
			if rule.Resource == resource {
				matched = append(matched, scopedRule{source: source, rule: rule})
			}
		}
	}
	for _, effect := range []Outcome{OutcomeDeny, OutcomeRequireApproval} {
		for _, rule := range matched {
			if Outcome(rule.rule.Effect) != effect {
				continue
			}
			if effect == OutcomeDeny {
				return fromSource(effect, rule.source, "resource:deny:"+resource, "resource denied"), nil
			}
			return fromSource(effect, rule.source, "resource:require_approval:"+resource, "resource requires approval"), nil
		}
	}
	if allowRules == 0 {
		return fromSource(OutcomeAllow, allowSource, "allowed:"+action, "allowed"), nil
	}
	for _, rule := range matched {
		if rule.rule.Effect == string(OutcomeAllow) {
			return fromSource(OutcomeAllow, rule.source, "resource:allow:"+resource, "resource allowed"), nil
		}
	}
	return Deny("resource not permitted"), nil
}

type scopedRule struct {
	source *Source
	rule   ResourceRule
}

func fromSource(outcome Outcome, source *Source, matchedRule string, reason string) Decision {
	decision := Decision{
		Outcome: outcome,
		Explanation: Explanation{
			MatchedRule: matchedRule,
			Reason:      reason,
		},
	}
	if source != nil {
		decision.Explanation.PolicyID = source.PolicyID
		decision.Explanation.Version = source.Version
		decision.PolicyVersionID = source.VersionID
	}
	return decision
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
