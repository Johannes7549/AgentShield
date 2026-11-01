# MCP integration

Status: implemented.

`GatewayMCPServer` speaks a small Model Context Protocol surface: `initialize`, `tools/list`, `ping`, and `tools/call`. `tools/call` forwards the name and arguments to `agentshield_sdk.Client.call_tool`. Tools are names, not functions. A name that was not listed returns a JSON-RPC error and does not run anything in this process.

`deny` and `require_approval` are MCP tool errors. The client does not execute those decisions.

```powershell
$env:PYTHONPATH = "sdk/python;integrations/mcp"
$env:AGENTSHIELD_GATEWAY = "http://127.0.0.1:8081"
$env:AGENTSHIELD_AGENT_ID = "<agent-uuid>"
$env:AGENTSHIELD_ORGANIZATION_ID = "<org-uuid>"
$env:AGENTSHIELD_SEED_FILE = "$env:TEMP\agentshield-sample.seed"
$env:AGENTSHIELD_TOOLS = "sample.echo"
python -m agentshield_mcp
```

The process speaks Content-Length framing on stdin and stdout. The gateway still executes only `sample.echo`.
