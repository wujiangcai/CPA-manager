$ErrorActionPreference = "Stop"

$targets = Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -and (
    $_.CommandLine -like '*cpa_usage_monitor.py*' -or
    $_.CommandLine -like '*account_pool_monitor.py*' -or
    $_.CommandLine -like '*cpa_detection_dashboard.py*'
  )
}

if (-not $targets) {
  Write-Host "No CPA detection process found."
  exit 0
}

$targets | ForEach-Object {
  Write-Host ("Stop PID " + $_.ProcessId + " " + $_.Name)
  Stop-Process -Id $_.ProcessId -Force
}
