# Sample agent

This directory is a demonstration of `sdk/python`. It is not a LangChain or LangGraph integration. The gateway executes only `sample.echo`. That adapter has no external side effect. Any other tool returns HTTP 501.

The script adds `sdk/python` to `sys.path`. Install the signature library once:

```powershell
python -m pip install -r examples/sample-agent/requirements.txt
python examples/sample-agent/agent.py --seed-file $env:TEMP\agentshield-sample.seed --agent-id <agent-uuid> --organization-id <org-uuid>
```

`--execute` sends a second signed request only when the decision is `allow`. The seed file is 32 bytes and is never sent.
