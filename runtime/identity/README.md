# Identity

Reference implementation of the AgentShield v1 request signature. See `docs/adr/0003-agent-identity.md`.

`Verify` checks the signature, the nonce shape, and a 60-second clock window. It does not remember nonces. Replay protection belongs in the gateway.
