# Fault injection

Status: implemented as fixtures inside the chaos harness.

The harness supplies a slow adapter, a repeated idempotency key, an unavailable dependency, an exhausted tool-call budget, and an expired credential. Those fixtures exercise the gateway's own code. This package is not a general-purpose attack tool and does not contain exploit payloads.
