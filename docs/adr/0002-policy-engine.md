# ADR 0002: In-process policy library, not OPA, for the first evaluator

- Status: Accepted
- Date: 2026-11-01

## Context

Policies are small documents: per-agent and per-organization allow, deny, and approval lists, plus resource constraints that narrow those lists. Evaluation must be deterministic, explained, and covered by tests that treat a mistake as a security bug. The gateway cannot wait on a second service to decide a tool call.

OPA and Rego are a proven policy system. They also add a language, a runtime, and an operational component the first contributors would have to learn before the first deny test exists. Embedding OPA in the gateway binary avoids a network hop but still leaves Rego as the source of truth for a document shape this product already fixed.

## Decision

Phase 1 implements an internal evaluator in `runtime/policy-engine`. The package already defines the only three outcomes and a fail-closed `Deny` helper. It does not yet evaluate documents. The evaluator, once added, must be a pure function of the policy documents and the request. It must not read the clock, the network, or the agent row.

The decision type is the extension point. A later revision can compile the same documents to Rego, or call OPA, if the Go function becomes a liability. That replacement has to preserve ADR 0004, including default deny.

## Consequences

We own precedence bugs until the evaluator is tested. That is acceptable because the rule set is small and the tests will name each precedence case. We do not own a Rego dialect.

The library must not grow storage clients. Loading policy remains the gateway's job.

## Alternatives

OPA as a sidecar was rejected for the hot path because a sidecar outage has to fail closed and would add a failure mode before we have a single policy test. Starting in Rego and hiding it behind the Go type was rejected because contributors would debug generated Rego instead of the rules they wrote.
