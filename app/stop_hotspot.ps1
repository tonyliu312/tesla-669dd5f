#requires -Version 5.1
<#
stop_hotspot.ps1 — 停掉热点模式起的三个组件（443 拦截 / DNS 劫持 / 看板 8900）

  .\stop_hotspot.ps1                  # 只停组件，热点保持
  .\stop_hotspot.ps1 -StopHotspot     # 连 FSD-PC 热点一起关
  .\stop_hotspot.ps1 -DryRun          # 只列会停哪些进程

不碰路由模式的常驻栈和 ARP 引流（那套用 stop_fsd_all.ps1）。
#>
[CmdletBinding()]
param([switch]$StopHotspot, [switch]$DryRun)

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$patterns = @('fsd_mock\.py', 'dns_sink\.py', 'fsd_panel\.py', '@443')

$targets = @(Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object {
        $proc = $_
        if (-not $proc.CommandLine) { return $false }
        @($patterns | Where-Object { $proc.CommandLine -match $_ }).Count -gt 0
    })

if ($targets.Count -eq 0) {
    Write-Host '没有在跑的热点模式组件。' -ForegroundColor Green
} else {
    foreach ($p in $targets) {
        if ($DryRun) {
            Write-Host ("[dry] pid={0}  {1}" -f $p.ProcessId, $p.CommandLine) -ForegroundColor DarkGray
        } else {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host ("已停 pid={0}" -f $p.ProcessId) -ForegroundColor Yellow
        }
    }
}

if ($StopHotspot -and -not $DryRun) {
    Write-Host '关闭热点...' -ForegroundColor Yellow
    & (Join-Path $root 'route-b.ps1') -Stop
}

if (-not $DryRun) {
    Write-Host '完成。车机侧重新连回原 Wi-Fi 即可恢复。' -ForegroundColor Green
}
