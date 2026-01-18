param(
    [string]$PidFile = "$PSScriptRoot\server.pid",
    [string]$LogOut = "$PSScriptRoot\server.out.log",
    [string]$LogErr = "$PSScriptRoot\server.err.log",
    [string]$Log = "$PSScriptRoot\server.log",
    [string]$NodeExe = 'D:\NodeJS\node.exe',
    [string]$Url = 'http://sqli-demo-app.local:3000'
)

Write-Host "Starting SQLi Demo App (PowerShell wrapper)..."
Write-Host "Logs: $LogOut (stdout), $LogErr (stderr), merged: $Log"

# If any node.exe process is already running server.js, treat that as the server and update pidfile
try {
    $existing = Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -and ($_.CommandLine -like '*server.js*') } | Select-Object -First 1
    if ($existing) {
        Set-Content -Path $PidFile -Value $existing.ProcessId -ErrorAction SilentlyContinue
        Write-Host "Detected existing node server (PID $($existing.ProcessId)); will reuse and open browser."
        $skipStart = $true
    }
} catch { }

function Is-ServerPidValid {
    param($pidFile)
    if (-not (Test-Path $pidFile)) { return $false }
    try {
        $pid = (Get-Content $pidFile -ErrorAction Stop).Trim()
        if (-not $pid) { return $false }
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
        if (-not $proc) { return $false }
        return $proc.CommandLine -like '*server.js*'
    } catch { return $false }
}
$serverRunning = $false
if ($skipStart) { $serverRunning = $true }
elseif (Is-ServerPidValid -pidFile $PidFile) { $serverRunning = $true; Write-Host "Detected running SQLi Demo server (tracked by $PidFile). Skipping start." }

if (-not $serverRunning) {
    # If pidfile exists but not valid, attempt to stop that PID and remove pidfile
    if (Test-Path $PidFile) {
        try { $old = (Get-Content $PidFile).Trim(); Stop-Process -Id $old -ErrorAction SilentlyContinue } catch { }
        Remove-Item -Path $PidFile -ErrorAction SilentlyContinue
    }

    # Best-effort: find any process listening on :3000 and stop it
    try {
        $portOwner = (netstat -ano | Select-String ':3000' | ForEach-Object { ($_ -split '\\s+')[-1] } | Select-Object -First 1)
        if ($portOwner) { Try { Stop-Process -Id $portOwner -Force -ErrorAction SilentlyContinue } Catch { } }
    } catch { }

    # Start node detached
    $startInfo = Start-Process -FilePath $NodeExe -ArgumentList 'server.js' -WorkingDirectory $PSScriptRoot -RedirectStandardOutput $LogOut -RedirectStandardError $LogErr -WindowStyle Minimized -PassThru
    if ($startInfo) {
        Set-Content -Path $PidFile -Value $startInfo.Id
        Write-Host "Launched node.exe (PID $($startInfo.Id))"
    } else {
        Write-Host "Failed to start node.exe"
    }
}

# Open the browser immediately so users see the app fast. The server listens
# right away and will serve a lightweight "Starting" page while DB seeding
# completes; this avoids long waits in the wrapper when seeding occurs.
Write-Host 'Opening demo host immediately (server may still be initializing)...'

# Prefer Chrome
$chrome1 = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$chrome2 = 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
if (Test-Path $chrome1) {
    Start-Process -FilePath $chrome1 -ArgumentList "--new-window",$Url
} elseif (Test-Path $chrome2) {
    Start-Process -FilePath $chrome2 -ArgumentList "--new-window",$Url
} else {
    Start-Process -FilePath $Url
}

# Merge logs for convenience
try { Get-Content $LogOut,$LogErr -ErrorAction SilentlyContinue | Out-File -FilePath $Log -Encoding utf8 } catch { }

Write-Host "Start wrapper finished. PID file: $PidFile, merged log: $Log"
 
