# auth-service#17 cutover: the on-host checklist, via SSM AWS-RunShellScript (no port forward, no Session Manager plugin).
# PowerShell 7, AWS CLI v2. Prints counts, docker status lines and at most 10 matching log lines per service (cut to 200
# characters); the services' logs never hold a token (their invariant), and no environment variable is printed.
#
#   pwsh ./scripts/cutover-hostcheck.ps1 -Since 2026-10-06T12:30:00Z [-Sha <40 hex tip of the cutover PR>]
#
# -Since is the time the rc deploy finished (cutover-deploy-rc.ps1 prints it). Read the output against the table at the end.
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')][string]$Since,
  [ValidatePattern('^[0-9a-f]{40}$')][string]$Sha
)
$ErrorActionPreference = 'Stop'
$Region = 'eu-central-1'
$InstanceId = 'i-011b6b82a9072a385'

# One shell script, __SINCE__ filled in. A single-quoted here-string: nothing is expanded by PowerShell.
$script = @'
echo "== 1 image (the mandatory gate)"
docker inspect auth-service --format 'image={{.Config.Image}} state={{.State.Status}} started={{.State.StartedAt}}'
echo "entrypoint_cmd=$(docker inspect auth-service --format '{{.Config.Entrypoint}} {{.Config.Cmd}}')"
echo "== 2 restarts, oom, memory cap, RSS"
docker ps --filter name=^auth-service$ --format 'status={{.Status}}'
docker inspect auth-service --format 'restarts={{.RestartCount}} oom={{.State.OOMKilled}} mem={{.HostConfig.Memory}}'
docker stats --no-stream --format 'rss={{.MemUsage}} cpu={{.CPUPerc}}' auth-service
echo "health_3005=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3005/health)"
echo "== 3 auth-service log since the deploy (failure lines; secrets are never logged)"
echo "typescript_start_line=$(docker logs auth-service 2>&1 | grep -c 'auth-service listening on :3005')"
echo "failure_lines=$(docker logs --since __SINCE__ auth-service 2>&1 | grep -ciE 'failed|upstream error|poller tick|error|fatal|panic')"
docker logs --since __SINCE__ auth-service 2>&1 | grep -iE 'failed|upstream error|poller tick|error|fatal|panic' | tail -n 10 | cut -c1-200
echo "== 3b what auth-service served since the deploy (request lines, counts only)"
echo "introspect_posts=$(docker logs --since __SINCE__ auth-service 2>&1 | grep -c 'POST request: to /auth/v1/introspect')"
echo "m2m_token_posts=$(docker logs --since __SINCE__ auth-service 2>&1 | grep -c 'POST request: to /auth/v1/m2m-token')"
echo "vault_token_gets=$(docker logs --since __SINCE__ auth-service 2>&1 | grep -c 'GET request: to /auth/v1/token')"
echo "m2m_mint_failures=$(docker logs --since __SINCE__ auth-service 2>&1 | grep -c 'minting a machine token')"
echo "== 4 automation-service log since the deploy (401|403|503 and m2m failures)"
echo "count_401_403_503=$(docker logs --since __SINCE__ automation-service 2>&1 | grep -ciE '401|403|503')"
echo "count_m2m_failures=$(docker logs --since __SINCE__ automation-service 2>&1 | grep -ciE 'm2m.*(fail|error|refus)')"
docker logs --since __SINCE__ automation-service 2>&1 | grep -iE '401|403|503|m2m.*(fail|error|refus)' | tail -n 10 | cut -c1-200
echo "== 4b ai-service (parked: expected not running; NOT PROBED)"
docker ps -a --filter name=^ai-service$ --format 'ai-service status={{.Status}}'
echo "== 5 the other introspection callers' logs since the deploy (401|403|503)"
for c in agent-service fleet-service navigation-service st-gateway; do echo "$c count_401_403_503=$(docker logs --since __SINCE__ $c 2>&1 | grep -ciE '401|403|503')"; done
echo "== 6 SQLite state, from the host (state and agent symbol; never a token)"
curl -s http://127.0.0.1:3005/api/auth/v1/status | cut -c1-300
echo
'@
$lines = ($script -replace '__SINCE__', $Since) -replace "`r", '' -split "`n"

$tmp = New-TemporaryFile
Set-Content -Path $tmp -Value (@{ commands = $lines } | ConvertTo-Json -Compress) -Encoding ascii
$id = aws ssm send-command --region $Region --document-name AWS-RunShellScript --targets "Key=InstanceIds,Values=$InstanceId" --parameters "file://$tmp" --query Command.CommandId --output text
Remove-Item $tmp
if ($LASTEXITCODE -ne 0 -or -not $id) { throw 'send-command failed' }
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Seconds 5
  $s = aws ssm get-command-invocation --region $Region --command-id $id --instance-id $InstanceId --query Status --output text 2>$null
  if ($s -and $s -notin 'Pending', 'InProgress', 'Delayed') { break }
}
"status: $s"
$out = aws ssm get-command-invocation --region $Region --command-id $id --instance-id $InstanceId --query StandardOutputContent --output text
$out
aws ssm get-command-invocation --region $Region --command-id $id --instance-id $InstanceId --query StandardErrorContent --output text

if ($Sha) {
  $want = "image=ghcr.io/v-m-pioneer-trading/auth-service:sha-$Sha "
  if (($out | Out-String).Contains($want)) { 'GATE PASS: the running image is the cutover PR tip.' } else { 'GATE FAIL: the running image is NOT sha-' + $Sha + '. Roll back.' }
}
@'

Read it like this (counts are since -Since):
  1  image=...:sha-<tip of the PR>, state=running; entrypoint_cmd is node + dist/server.js (the Go image's is /main).
  2  restarts=0 oom=false, mem=<the cap in bytes, non-zero>, health_3005=200; record rss.
  3  typescript_start_line >= 1 (only the TypeScript service logs it); failure_lines = 0, or read each printed line.
  3b introspect_posts > 0 (the callers and st-gateway's lane deriver), m2m_token_posts > 0 once automation-service has
     minted (its token lives 24 h, so a restart or a first mint is what shows it), vault_token_gets > 0 (st-gateway's token
     fetch: with the signed-in /api/agent/v1/agent 200 from the probe it proves the vault route), m2m_mint_failures = 0.
  4  automation-service: both counts 0 (no 401/503 from the M2M mint). ai-service is parked: NOT PROBED.
  5  every count 0.
  6  the SAME agent symbol as before the cutover (record the symbol, never a token).
'@
