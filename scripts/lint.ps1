$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$bundledGo = Join-Path $Root ".tools\go\bin"
if (Test-Path (Join-Path $bundledGo "go.exe")) {
  $env:Path = "$bundledGo;$env:Path"
}

Write-Host "== gofmt =="
$unformatted = gofmt -l runtime
if ($unformatted) {
  Write-Host $unformatted
  exit 1
}

Write-Host "== ruff =="
python -m ruff check apps/intelligence-engine tests sdk/python integrations examples/sample-agent
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "== tsc =="
npm run lint
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
