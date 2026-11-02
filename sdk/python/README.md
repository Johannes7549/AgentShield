# Python SDK

Status: implemented.

`agentshield_sdk` signs the exact bytes it sends to the gateway:

```text
<unix-seconds>.<nonce>.<lowercase-hex sha256 of the raw request body>
```

The private seed stays in the caller process. `call_tool` calls `execute` only when the gateway outcome is `allow`. `deny` and `require_approval` stop. `execute` accepts an approval id after a human has approved that decision. The client has no method that runs a tool locally.

```powershell
python -m pip install cryptography
$env:PYTHONPATH = "sdk/python"
```

The gateway still executes only `sample.echo`. Any other tool comes back as HTTP 501 from the gateway.
