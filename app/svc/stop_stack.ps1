#requires -Version 5.1
<#
stop_stack.ps1 — 停掉常驻栈（stack.py + dns + reverse + proxy + web）

  .\svc\stop_stack.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
Get-Process python, pythonw, mitmdump -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like 'C:\fsd-mitm\venv*' } |
    ForEach-Object {
        Write-Host "kill $($_.Id) $($_.ProcessName)"
        & taskkill.exe /PID $_.Id /T /F *> $null
    }
Start-Sleep -Seconds 1
foreach ($port in 4567, 8080, 8899) {
    $alive = $false
    try { $c = New-Object System.Net.Sockets.TcpClient; $alive = $c.ConnectAsync('127.0.0.1', $port).Wait(400); $c.Dispose() } catch { }
    Write-Host ("{0}: {1}" -f $port, $(if ($alive) { 'still open' } else { 'closed' }))
}
