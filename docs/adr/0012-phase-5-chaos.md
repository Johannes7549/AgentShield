# ADR 0012: Phase 5 chaos harness

- Status: Accepted
- Date: 2026-11-02

## Context

The catalog names twelve defensive properties. The control-plane routes for experiments returned 501 because no runner existed, and a success response before a runner would hide a missed check. `chaos_scenarios.enabled` stayed false until a harness could fail a scenario when the expected behavior was not observed.

## Decision

`runtime/gateway/internal/chaos` runs each catalog scenario against the gateway's real authorization, limit, timeout, and body-limit code, using fixtures rather than attack payloads. The judge returns failed when the observation is missing or the defense did not hold. Unknown scenario ids return error.

Owner and admin sessions can start and read an experiment. The control plane stores the harness result on `chaos_executions`. Status `passed` is stored only when the harness observed the property. A disabled scenario returns 409. The catalog rows are inserted enabled. The dashboard still does not launch experiments.

## Consequences

`POST /api/v1/chaos/experiments` returns 201 with the stored result instead of 501. Event and audit reads stay closed. The harness does not change allow, deny, or require_approval, and it does not add a model score.

## Alternatives

Treating a missing observation as a pass was rejected. Returning 501 after the runner existed was rejected because the contract said that status lasted only until a runner existed. Shipping exploit strings in the catalog was rejected.
