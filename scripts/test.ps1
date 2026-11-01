$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$bundledGo = Join-Path $Root ".tools\go\bin"
if (Test-Path (Join-Path $bundledGo "go.exe")) {
  $env:Path = "$bundledGo;$env:Path"
}

Write-Host "== go test =="
go test ./runtime/gateway/... ./runtime/identity/... ./runtime/policy-engine/...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "== repository contracts =="
python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "== intelligence engine =="
$env:PYTHONPATH = "apps/intelligence-engine"
python -m unittest discover -s apps/intelligence-engine/tests -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "== node =="
npm test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
