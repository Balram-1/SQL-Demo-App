param([string]$pidFile)

if (Test-Path $pidFile) {
  try {
    $filePid = [int](Get-Content $pidFile -ErrorAction Stop)
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$filePid" -ErrorAction SilentlyContinue
    if ($proc -and $proc.CommandLine -match 'server.js') {
      Write-Output 'RUNNING'
      exit 0
    }
  } catch {}
}
Write-Output 'NOTRUNNING'
exit 1
