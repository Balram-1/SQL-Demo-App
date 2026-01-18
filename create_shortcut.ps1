# Creates a desktop shortcut that runs start.bat hidden
param(
    [string]$ShortcutName = 'SQLi Demo Start.lnk',
    [string]$TargetScript = "$PSScriptRoot\\start.bat"
)

$ws = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$linkPath = Join-Path $desktop $ShortcutName

$cmd = "$env:COMSPEC"
$args = "/c start """" /min `"$TargetScript`""

$shortcut = $ws.CreateShortcut($linkPath)
$shortcut.TargetPath = $cmd
$shortcut.Arguments = $args
$shortcut.WorkingDirectory = Split-Path -Parent $TargetScript
$shortcut.IconLocation = "$env:SystemRoot\\System32\\shell32.dll, 220"
$shortcut.WindowStyle = 7
$shortcut.Save()

Write-Output "Shortcut created: $linkPath"
