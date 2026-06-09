$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$StopDetection = Join-Path $Root "stop_all.ps1"

if (Test-Path -LiteralPath $StopDetection) {
  Write-Host "Stopping CPA detection services..."
  powershell -NoProfile -ExecutionPolicy Bypass -File $StopDetection
} else {
  Write-Host "Detection stop script not found: $StopDetection"
}

$cliTargets = Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -and $_.CommandLine -like '*cli-proxy-api*'
}

if (-not $cliTargets) {
  Write-Host "No CLIProxyAPI process found."
} else {
  $cliTargets | ForEach-Object {
    Write-Host ("Stop CLIProxyAPI PID " + $_.ProcessId + " " + $_.Name)
    Stop-Process -Id $_.ProcessId -Force
  }
}

Write-Host "All services stopped."
