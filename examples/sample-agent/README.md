# Sample Python agent

This directory is a demonstration, not a Python SDK and not a LangChain integration. The gateway executes only `sample.echo`. That adapter has no external side effect. Any other tool returns HTTP 501.

The seed file is the Ed25519 private key. Do not commit it and do not send it to the control plane. Register the printed public key.

```powershell
python -m pip install -r examples/sample-agent/requirements.txt
python examples/sample-agent/agent.py --seed-file $env:TEMP\agentshield-sample.seed --agent-id <agent-uuid> --organization-id <org-uuid>
```

The first run creates the seed and prints `public_key`. Create the agent and an organization policy that allows `sample.echo` before expecting `allow`. Add `--execute` only after authorize returns `allow`.

`database.export` is a useful deny check when the policy denies it. `email.send` returns `require_approval` and stops. This script cannot approve that request.
