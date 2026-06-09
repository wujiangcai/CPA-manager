$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = (Get-Command python -ErrorAction Stop).Source

function Stop-Old {
  Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -and (
      $_.CommandLine -like '*cpa_usage_monitor.py*' -or
      $_.CommandLine -like '*account_pool_monitor.py*' -or
      $_.CommandLine -like '*cpa_detection_dashboard.py*'
    )
  } | ForEach-Object {
    Write-Host ("Stop PID " + $_.ProcessId + " " + $_.Name)
    Stop-Process -Id $_.ProcessId -Force
  }
}

function Start-Python($Name, $Script, $WorkDir, $Stdout, $Stderr) {
  if (-not (Test-Path -LiteralPath $Script)) {
    throw "$Name script not found: $Script"
  }
  Start-Process -FilePath $Python -ArgumentList @('-u', $Script) -WorkingDirectory $WorkDir -WindowStyle Hidden -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr | Out-Null
}

Stop-Old
Start-Sleep -Seconds 1

$UsageDir = Join-Path $Root "RUN_ON_YOUR_PC"
$PoolDir = Join-Path $Root "account_pool_monitor"

Start-Python "usage monitor" (Join-Path $UsageDir "cpa_usage_monitor.py") $UsageDir (Join-Path $UsageDir "cpa_usage_monitor_stdout.log") (Join-Path $UsageDir "cpa_usage_monitor_stderr.log")
Start-Python "account pool monitor" (Join-Path $PoolDir "account_pool_monitor.py") $PoolDir (Join-Path $PoolDir "account_pool_monitor_stdout.log") (Join-Path $PoolDir "account_pool_monitor_stderr.log")
Start-Python "dashboard" (Join-Path $Root "cpa_detection_dashboard.py") $Root (Join-Path $Root "cpa_detection_dashboard_stdout.log") (Join-Path $Root "cpa_detection_dashboard_stderr.log")

Start-Sleep -Seconds 3
Write-Host "usage ping:"
curl.exe -s http://127.0.0.1:18319/ping
Write-Host ""
Write-Host "account pool ping:"
curl.exe -s http://127.0.0.1:18320/api/ping
Write-Host ""
Write-Host "dashboard ping:"
curl.exe -s http://127.0.0.1:18321/api/ping
Write-Host ""
