#requires -Version 3.0
<# stop_fsd_all.ps1 — 停掉整套 FSD 拦截环境（看门狗一起停，否则会被拉起） #>
$root = $PSScriptRoot
Write-Host '停止看门狗...' -ForegroundColor Yellow
Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -match 'supervise_all\.py' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Write-Host '停止 ARP 引流 / 443 拦截 / 看板 / 常驻栈...' -ForegroundColor Yellow
foreach ($pat in @('arp_mitm\.py','fsd_panel\.py','@443')) {
  Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match $pat } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
& (Join-Path $root 'svc\stop_stack.ps1') | Out-Null
Start-Sleep -Seconds 2
Write-Host '已停止。车机约 1 分钟内恢复直连。' -ForegroundColor Green