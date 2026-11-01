# Policy engine

Go library for deterministic authorization. The decision type and the fail-closed `Deny` helper are implemented. An evaluator is not.

Rules for the evaluator that Phase 1 must implement are in `docs/adr/0004-authorization-decisions.md`. Do not add an `Evaluate` function that returns allow when policy is missing.
