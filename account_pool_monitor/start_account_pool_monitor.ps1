$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script = Join-Path $Root "account_pool_monitor.py"
$Stdout = Join-Path $Root "account_pool_monitor_stdout.log"
$Stderr = Join-Path $Root "account_pool_monitor_stderr.log"

$existing = Get-CimInstance Win32_Process | Where-Object {
  $_.Name -like "python*" -and $_.CommandLine -and $_.CommandLine -like "*account_pool_monitor.py*"
}

if ($existing) {
  $existing | ForEach-Object {
    Write-Host ("Stop old PID " + $_.ProcessId)
    Stop-Process -Id $_.ProcessId -Force
  }
  Start-Sleep -Seconds 1
}

$python = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $python) {
  $python = (Get-Command py -ErrorAction SilentlyContinue)
}
if (-not $python) {
  throw "Python was not found in PATH."
}
Start-Process -FilePath $python.Source -ArgumentList @("-u", $Script) -WorkingDirectory $Root -WindowStyle Hidden -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr
Start-Sleep -Seconds 3

$ping = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:18320/api/ping" -TimeoutSec 5
Write-Host "ping:"
Write-Host $ping.Content
