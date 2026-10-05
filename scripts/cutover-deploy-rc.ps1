# auth-service#17 cutover, steps 2 + 4: deploy the rc image by sha, wait, then check on the host which image runs.
# PowerShell 7, AWS CLI v2 with credentials for eu-central-1. No Session Manager plugin needed: the host is reached with
# AWS-RunShellScript only. Prints statuses, image names and the public agent symbol; never a token or an SSM output beyond
# the few docker lines below. Modeled on the script that ran agent-service#51's cutover.
#
#   pwsh ./scripts/cutover-deploy-rc.ps1 -Sha <40 hex: the tip of the cutover PR, the commit the v2.0.0-rc.N tag points at>
#
# Order of the procedure (the PR description has the whole list):
#   0. the infrastructure PR with `--memory` on auth-service's docker run is merged AND APPLIED. Not during the freeze:
#      an apply re-runs the bootstrap with `:latest`, which is the Go image until the cutover merges.
#   1. the v* tag is pushed and `container.yml` finished: ghcr.io/v-m-pioneer-trading/auth-service:sha-<Sha> exists.
#   2. run THIS script (merge freeze on auth-service from here until the probe is green; no terraform apply).
#   3. node scripts/cutover-probe.mjs --strict ...   4. pwsh ./scripts/cutover-hostcheck.ps1 -Since <the time this prints>
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Sha,
  # The last Go image (the tip of main that deployed it). Printed as the rollback command at the end.
  [ValidatePattern('^[0-9a-f]{40}$')][string]$RollbackSha = '8a09f84d8898e4e1bd1428cce264250ab9ce78d1',
  [string]$BaseUrl = 'https://spacetraders.radomskyi.com',
  # Skip the "the memory cap is already applied" pre-flight (only if the owner knows better).
  [switch]$SkipMemoryCheck
)
$ErrorActionPreference = 'Stop'
$Region = 'eu-central-1'
$InstanceId = 'i-011b6b82a9072a385'
$Document = "auth-service-bootstrap-$InstanceId"
$Image = "ghcr.io/v-m-pioneer-trading/auth-service:sha-$Sha"

function Wait-Command($id, $tries = 90) {
  for ($i = 0; $i -lt $tries; $i++) {
    Start-Sleep -Seconds 10
    $s = aws ssm get-command-invocation --region $Region --command-id $id --instance-id $InstanceId --query Status --output text 2>$null
    if (-not $s) { $s = 'Pending' }
    Write-Host "  $s"
    if ($s -notin 'Pending', 'InProgress', 'Delayed') { return $s }
  }
  return 'Timeout'
}

# Runs shell lines on the host with AWS-RunShellScript and prints the stdout. Returns the stdout as one string.
function Invoke-Host([string[]]$Lines) {
  $tmp = New-TemporaryFile
  try {
    Set-Content -Path $tmp -Value (@{ commands = $Lines } | ConvertTo-Json -Compress) -Encoding ascii
    $id = aws ssm send-command --region $Region --document-name AWS-RunShellScript `
      --targets "Key=InstanceIds,Values=$InstanceId" --parameters "file://$tmp" `
      --query Command.CommandId --output text
    if ($LASTEXITCODE -ne 0 -or -not $id) { throw 'send-command (AWS-RunShellScript) failed' }
  } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
  $status = Wait-Command $id 30
  $out = aws ssm get-command-invocation --region $Region --command-id $id --instance-id $InstanceId --query StandardOutputContent --output text
  if ($status -ne 'Success') { Write-Host "  host command ended: $status"; aws ssm get-command-invocation --region $Region --command-id $id --instance-id $InstanceId --query StandardErrorContent --output text }
  return ($out | Out-String)
}

# The public status route: the state and the agent symbol (never a token). The symbol must be the same before and after.
function Get-AgentSymbol([string]$When) {
  try {
    $s = Invoke-RestMethod -Uri "$BaseUrl/api/auth/v1/status" -TimeoutSec 20
    $sym = if ($s.PSObject.Properties.Name -contains 'agentSymbol') { [string]$s.agentSymbol } else { '(none)' }
    Write-Host "  status $When`: state=$($s.state) agentSymbol=$sym"
    return $sym
  } catch {
    Write-Host "  status $When`: could not be read ($($_.Exception.Message))"
    return '(unreadable)'
  }
}

Write-Host "Pre-flight"
try { $main = (gh run list -R V-M-Pioneer-Trading/auth-service --workflow container --branch main --status in_progress --json databaseId --jq 'length' 2>$null) } catch { $main = $null; Write-Host '  (gh is not available: check by hand that the CI deploy on main is idle)' }
if ($main -and [int]$main -gt 0) { throw "main's CI deploy is running ($main run(s) in progress): wait for it, or it will race this deploy." }
$before = Get-AgentSymbol 'BEFORE'
if (-not $SkipMemoryCheck) {
  $mem = (Invoke-Host @("docker inspect auth-service --format 'mem={{.HostConfig.Memory}} image={{.Config.Image}}'")).Trim()
  Write-Host "  $mem"
  if ($mem -notmatch 'mem=([0-9]+)' -or [int64]$Matches[1] -le 0) {
    throw 'The running auth-service has no memory cap. Apply the infrastructure PR (--memory on auth-service) FIRST, before this deploy: an apply after it would redeploy :latest (Go).'
  }
}

Write-Host "Step 2: deploying $Image"
$id = aws ssm send-command --region $Region --document-name $Document `
  --targets "Key=InstanceIds,Values=$InstanceId" --parameters "imageTag=sha-$Sha" `
  --timeout-seconds 600 --query Command.CommandId --output text
if ($LASTEXITCODE -ne 0 -or -not $id) { throw 'send-command failed' }
Write-Host "  command $id"
$status = Wait-Command $id
$finished = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Write-Host "Deploy status: $status (finished ~ ${finished}: use it as SINCE for the probe and as -Since for the host check)"
if ($status -ne 'Success') { Write-Host 'NOT Success: roll back (command below) and look at the SSM console output for this command ID.' }

Write-Host "Step 4: the image that runs on the host (the mandatory gate)"
$inspect = Invoke-Host @(
  "docker inspect auth-service --format 'image={{.Config.Image}} state={{.State.Status}} restarts={{.RestartCount}} oom={{.State.OOMKilled}} mem={{.HostConfig.Memory}}'",
  "docker stats --no-stream --format 'rss={{.MemUsage}}' auth-service",
  "echo health=`$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3005/health)"
)
Write-Host $inspect
Write-Host "Expected: image=$Image state=running restarts=0 oom=false mem=<non-zero> health=200"
if ($inspect -match [regex]::Escape("image=$Image ") -and $inspect -match 'state=running') {
  Write-Host 'GATE PASS: the running image is the cutover PR tip.'
} else {
  Write-Host 'GATE FAIL: the running image is NOT the cutover PR tip. Every outside probe is meaningless; roll back.'
}

Write-Host "After the deploy"
$after = Get-AgentSymbol 'AFTER'
if ($before -eq $after -and $before -notin '(none)', '(unreadable)') { Write-Host "SQLITE STATE: the agent symbol is the same before and after ($after). EXPECT_AGENT_SYMBOL=$before" }
else { Write-Host "SQLITE STATE: CHECK. before=$before after=$after. Export EXPECT_AGENT_SYMBOL only if 'before' was read from the Go image." }

Write-Host ""
Write-Host "Next: node scripts/cutover-probe.mjs --strict   with SINCE=$finished and EXPECT_AGENT_SYMBOL=$before (the PR description lists the variables)"
Write-Host ""
Write-Host "Rollback if anything is red (the last Go image; a rollback is not sticky, see the revert-PR rule in the PR):"
Write-Host "  aws ssm send-command --region $Region --document-name $Document --targets Key=InstanceIds,Values=$InstanceId --parameters imageTag=sha-$RollbackSha --timeout-seconds 600 --query Command.CommandId --output text"
