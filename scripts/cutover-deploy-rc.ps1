# auth-service#17 cutover (PR #26), steps 2 + 4 + 4b: deploy the rc image by sha, wait, check on the host which image runs,
# then restart automation-service so the probe exercises the TypeScript M2M mint.
# PowerShell 7, AWS CLI v2 with credentials for eu-central-1, and the GitHub CLI (gh). No Session Manager plugin needed:
# the host is reached with AWS-RunShellScript only. Prints statuses, image names and the public agent symbol; never a
# token or an SSM output beyond the few docker lines below. Modeled on the script that ran agent-service#51's cutover.
#
#   pwsh ./scripts/cutover-deploy-rc.ps1 -Sha <40 hex: the tip of the cutover PR, the commit the v2.0.0-rc.N tag points at>
#
# Order of the procedure (the PR description has the whole list):
#   0. the infrastructure memory-cap PR (infrastructure#104, merged) is APPLIED. Not during the freeze: an apply re-runs
#      the bootstrap with `:latest`, which is the Go image until the cutover merges. This script refuses to deploy if the
#      running container has no memory cap.
#   1. the v* tag is pushed and `container.yml` finished: ghcr.io/v-m-pioneer-trading/auth-service:sha-<Sha> exists.
#   2. run THIS script (merge freeze on auth-service from here until the probe is green; no terraform apply).
#      The autopilot should be armed in SHADOW mode already (the probe's hard gate needs it).
#   3. only if the GATE passes it restarts automation-service (docker restart): its 24 h M2M token cache is emptied, so its
#      next call mints a token through POST /auth/v1/m2m-token on THIS auth-service. Without that the probe would pass on a
#      token Go minted up to 24 h ago, and the first real TypeScript mint would be 12 h after the merge.
#   4. node scripts/cutover-probe.mjs --strict (SINCE = RESTARTED_AT) when automation has had a planner cycle, then
#      pwsh ./scripts/cutover-hostcheck.ps1 -Since <RESTARTED_AT> -Sha <Sha>
param(
  # (?-i:...): ValidatePattern is case-insensitive by default; a sha is lowercase hex.
  [Parameter(Mandatory = $true)][ValidatePattern('^(?-i:[0-9a-f]{40})$')][string]$Sha,
  # The last Go image (the tip of main that deployed it). Printed as the rollback command at the end.
  [ValidatePattern('^(?-i:[0-9a-f]{40})$')][string]$RollbackSha = '8a09f84d8898e4e1bd1428cce264250ab9ce78d1',
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

# Runs shell lines on the host with AWS-RunShellScript. Returns the stdout as one string (and only that: everything else,
# stderr included, goes to the console through Write-Host).
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
  if ($status -ne 'Success') {
    Write-Host "  host command ended: $status"
    Write-Host (aws ssm get-command-invocation --region $Region --command-id $id --instance-id $InstanceId --query StandardErrorContent --output text | Out-String)
  }
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

function Write-Rollback {
  Write-Host ""
  Write-Host "Rollback if anything is red (the last Go image; a rollback is not sticky, see the revert-PR rule in the PR):"
  Write-Host "  aws ssm send-command --region $Region --document-name $Document --targets Key=InstanceIds,Values=$InstanceId --parameters imageTag=sha-$RollbackSha --timeout-seconds 600 --query Command.CommandId --output text"
}

Write-Host "Pre-flight"
# Fails closed: a gh error, an unreadable answer or ANY run of the container workflow on main that is not completed
# (queued, pending, waiting, requested, in_progress) stops the script. A merge's deploy racing this one would put :latest
# (Go) back on the host.
$busy = gh run list -R V-M-Pioneer-Trading/auth-service --workflow container --branch main --limit 20 --json status --jq '[.[] | select(.status != "completed")] | length'
if ($LASTEXITCODE -ne 0 -or "$busy".Trim() -notmatch '^[0-9]+$') { throw "Could not read main's workflow runs with gh (exit $LASTEXITCODE). Fix gh (gh auth status) and run again: the script does not deploy blind." }
if ([int]"$busy".Trim() -gt 0) { throw "main's CI deploy is busy ($busy run(s) not completed): wait for it, or it will race this deploy." }
$before = Get-AgentSymbol 'BEFORE'
if (-not $SkipMemoryCheck) {
  $mem = (Invoke-Host @("docker inspect auth-service --format 'mem={{.HostConfig.Memory}} image={{.Config.Image}}'")).Trim()
  Write-Host "  $mem"
  if ($mem -notmatch 'mem=([0-9]+)' -or [int64]$Matches[1] -le 0) {
    throw 'The running auth-service has no memory cap. APPLY the infrastructure memory-cap PR (infrastructure#104, --memory on auth-service) FIRST, before this deploy: an apply after it would redeploy :latest (Go).'
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
Write-Host "Deploy status: $status (finished ~ ${finished})"

Write-Host "Step 4: the image that runs on the host (the mandatory gate)"
$inspect = Invoke-Host @(
  "docker inspect auth-service --format 'image={{.Config.Image}} state={{.State.Status}} restarts={{.RestartCount}} oom={{.State.OOMKilled}} mem={{.HostConfig.Memory}}'",
  "docker stats --no-stream --format 'rss={{.MemUsage}}' auth-service",
  'echo health=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3005/health)'
)
Write-Host $inspect
Write-Host "Expected: deploy Success, image=$Image state=running restarts=0 oom=false mem=<non-zero> health=200"
$why = @()
if ($status -ne 'Success') { $why += "deploy status is $status, not Success" }
if (-not $inspect.Contains("image=$Image ")) { $why += 'the running image is not the cutover PR tip' }
if ($inspect -notmatch 'state=running') { $why += 'state is not running' }
if ($inspect -notmatch 'restarts=0(\s|$)') { $why += 'restarts is not 0 (crash loop?)' }
if ($inspect -notmatch '(?m)^health=200\s*$') { $why += 'GET /health on 127.0.0.1:3005 is not 200' }
$gate = ($why.Count -eq 0)
if ($gate) { Write-Host 'GATE PASS: deploy Success, the running image is the cutover PR tip, running, restarts=0, /health 200.' }
else {
  Write-Host "GATE FAIL: $($why -join '; '). Every outside probe is meaningless; roll back (command below) and read the SSM console output for command $id."
  Write-Rollback
  exit 1
}

Write-Host "Step 4b: restarting automation-service (empties its 24 h M2M token cache: the next call mints through THIS auth-service)"
$rs = Invoke-Host @(
  'docker restart automation-service > /dev/null && echo restarted_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)',
  "docker inspect automation-service --format 'automation-service state={{.State.Status}} restarts={{.RestartCount}}'"
)
Write-Host $rs
if ($rs -notmatch 'restarted_at=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)') { Write-Host 'The restart did not report a time: do it by hand (docker restart automation-service) and note the UTC time.'; exit 1 }
$restartedAt = $Matches[1]
Write-Host "RESTARTED_AT=$restartedAt (SINCE for the probe, -Since for the host check). ai-service: NOT PROBED (parked, not deployed)."

Write-Host "After the deploy"
$after = Get-AgentSymbol 'AFTER'
if ($before -eq $after -and $before -notin '(none)', '(unreadable)') { Write-Host "SQLITE STATE: the agent symbol is the same before and after ($after). EXPECT_AGENT_SYMBOL=$before" }
else { Write-Host "SQLITE STATE: CHECK. before=$before after=$after. Export EXPECT_AGENT_SYMBOL only if 'before' was read from the Go image." }

Write-Host ""
Write-Host "Next: wait for a planner cycle (a minute or two), then node scripts/cutover-probe.mjs --strict   with SINCE=$restartedAt and EXPECT_AGENT_SYMBOL=$before"
Write-Host "      then pwsh ./scripts/cutover-hostcheck.ps1 -Since $restartedAt -Sha $Sha"
Write-Rollback
