# Intelligence engine

Python process reserved for prompt-injection classification, behavioral scoring, and incident investigation.

Nothing in this package classifies content. `analyze_untrusted_content` raises `AnalysisUnavailable` and does not echo the input. There is no HTTP analysis route. A future detection result is not an authorization decision.

```powershell
$env:PYTHONPATH = "apps/intelligence-engine"
python -m agentshield_intelligence
```

`GET /health/live` returns 200. `GET /health/ready` returns 503. The process listens on `127.0.0.1:8082` and refuses production mode.
