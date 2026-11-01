# ADR 0004: Authorization outcomes and precedence

- Status: Accepted
- Date: 2026-11-01

## Context

Lists of allowed, denied, and approval-required actions will disagree once an organization policy and an agent policy are both active. The gateway needs one rule that an implementer cannot "simplify" into a first-match allow.

## Decision

Outcomes are `allow`, `deny`, and `require_approval`. Names are case sensitive.

Given the active organization document and the active agent document:

1. If the action appears in either document's deny list, the outcome is `deny`.
2. Otherwise, if the action appears in either document's approval list, the outcome is `require_approval`.
3. Otherwise, if the action appears in either document's allow list, the outcome is `allow`.
4. Otherwise the outcome is `deny`.

A document must not place the same action in more than one of its own lists. That is a validation error, not a case for the precedence rule.

Resource rules select when an action rule applies. They cannot grant an action that step 3 would not already allow, and they cannot remove a deny. A resource that does not match means the rule does not apply. An unmatched allow is not a deny by itself if another allow still matches. If no allow or approval applies after resource selection, the outcome is `deny`.

Missing policy documents follow rule 4. A database error follows the same external behavior as deny and does not call the tool. The evaluator returns an error or `Deny`. It does not return a default allow.

`agent_permissions` is not an input to this function.

## Consequences

An organization deny cannot be overridden by an agent allow. An agent can be stricter than the organization by adding a deny or an approval. An agent cannot become more permissive than the organization.

Phase 1 tests must cover each numbered rule, a cross-document deny, a cross-document approval, an unknown action, and a failed policy load.

## Alternatives

First matching rule was rejected because document order would become a security property. Allow-overrides-deny was rejected because a narrower agent policy could not contain a mistake in a broader one, and a compromised policy writer could hide a grant under an allow.
