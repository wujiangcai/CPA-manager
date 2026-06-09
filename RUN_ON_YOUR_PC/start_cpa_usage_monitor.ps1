$ErrorActionPreference = 'Stop'

$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Join-Path $dir 'cpa_usage_monitor.py'
$stdout = Join-Path $dir 'cpa_usage_monitor_stdout.log'
$stderr = Join-Path $dir 'cpa_usage_monitor_stderr.log'

if (-not (Test-Path -LiteralPath $script)) {
  throw "cpa_usage_monitor.py not found: $script"
}

$python = Get-Command python -ErrorAction Stop

Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -and $_.CommandLine -like '*cpa_usage_monitor.py*'
} | ForEach-Object {
  Stop-Process -Id $_.ProcessId -Force
}

Start-Sleep -Seconds 1
Start-Process -FilePath $python.Source -ArgumentList @('-u', $script) -WorkingDirectory $dir -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr | Out-Null
Start-Sleep -Seconds 2
curl.exe -s http://127.0.0.1:18319/ping
