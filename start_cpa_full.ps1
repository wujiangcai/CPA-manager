$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$CliDir = Join-Path $Root "CLIProxyAPI_release"
$CliExe = Join-Path $CliDir "cli-proxy-api.exe"
$CliConfig = Join-Path $CliDir "config.yaml"
$StartDetection = Join-Path $Root "start_all.ps1"

function Stop-OldCliProxyApi {
  Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -and $_.CommandLine -like '*cli-proxy-api*'
  } | ForEach-Object {
    Write-Host ("Stop CLIProxyAPI PID " + $_.ProcessId + " " + $_.Name)
    Stop-Process -Id $_.ProcessId -Force
  }
}

if (-not (Test-Path -LiteralPath $CliExe)) {
  throw "CLIProxyAPI executable not found: $CliExe"
}
if (-not (Test-Path -LiteralPath $CliConfig)) {
  throw "CLIProxyAPI config not found: $CliConfig"
}
if (-not (Test-Path -LiteralPath $StartDetection)) {
  throw "Detection start script not found: $StartDetection"
}

Stop-OldCliProxyApi
Start-Sleep -Seconds 1

New-Item -ItemType Directory -Force (Join-Path $CliDir "auths") | Out-Null

Write-Host "Starting CLIProxyAPI..."
Start-Process -FilePath $CliExe `
  -ArgumentList @('--config', $CliConfig, '--no-browser', '--local-model') `
  -WorkingDirectory $CliDir `
  -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $CliDir "cli-proxy-api_stdout.log") `
  -RedirectStandardError (Join-Path $CliDir "cli-proxy-api_stderr.log") | Out-Null

Start-Sleep -Seconds 3
Write-Host "CLIProxyAPI ping:"
curl.exe -s -H "Authorization: Bearer cpa-local-key" http://127.0.0.1:8317/v1/models
Write-Host ""

Write-Host "Starting CPA detection services..."
powershell -NoProfile -ExecutionPolicy Bypass -File $StartDetection

Write-Host ""
Write-Host "All services started."
Write-Host "CLIProxyAPI panel: http://127.0.0.1:8317/"
Write-Host "Detection dashboard: http://127.0.0.1:18321/"
Write-Host "Usage monitor: http://127.0.0.1:18319/"
Write-Host "Account pool monitor: http://127.0.0.1:18320/"
