#requires -Version 5.1
<#
Clear-FSD-Records.ps1 — 清空看板记录（只动 <项目>\logs 里的记录文件）

  .\Clear-FSD-Records.ps1            # 预演：只列出将删除的文件和体积，不动手
  .\Clear-FSD-Records.ps1 -Force     # 真删

会删：hits.jsonl / dns.jsonl / arp_mitm.log / handshake.log / car_recent.jsonl /
      config_history.jsonl / requests\ / *.log / __pycache__
不删：logs 目录本身、payload.json、payload.json.bak、certs、任何源码

为什么这样做：看板（8900）是只读的，页面上所有记录都来自 logs\ —— 清 logs 即清看板。
看板在跑时不影响，刷新页面即为空；不放心可先 stop_fsd_all.ps1。
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [string]$Root = 'C:\fsd-mitm'
)

$ErrorActionPreference = 'Stop'
$logs = Join-Path $Root 'logs'

if (-not (Test-Path -LiteralPath $logs)) {
    Write-Host "没有 logs 目录：$logs" -ForegroundColor Yellow
    Write-Host '看板本来就没有记录。' -ForegroundColor Green
    return
}

$targets = @(Get-ChildItem -LiteralPath $logs -Force -ErrorAction SilentlyContinue)
if ($targets.Count -eq 0) {
    Write-Host "logs 已空：$logs" -ForegroundColor Green
    Write-Host '看板没有记录可删。' -ForegroundColor Green
    return
}

$total = 0
Write-Host ''
Write-Host "将清理：$logs" -ForegroundColor Cyan
foreach ($t in $targets) {
    $size = 0
    if ($t.PSIsContainer) {
        $size = (Get-ChildItem -LiteralPath $t.FullName -Recurse -File -ErrorAction SilentlyContinue |
                 Measure-Object Length -Sum).Sum
    } else {
        $size = $t.Length
    }
    if (-not $size) { $size = 0 }
    $total += $size
    Write-Host ("  {0,-44} {1,10:N1} KB" -f $t.Name, ($size / 1KB))
}
Write-Host ("  合计 {0:N1} KB / {1} 项" -f ($total / 1KB), $targets.Count) -ForegroundColor DarkGray

if (-not $Force) {
    Write-Host ''
    Write-Host '这是预演，什么都没删。确认执行：' -ForegroundColor Yellow
    Write-Host '  .\Clear-FSD-Records.ps1 -Force' -ForegroundColor Yellow
    return
}

# 只删 logs 下的条目，绝不删 logs 目录本身
foreach ($t in $targets) {
    Remove-Item -LiteralPath $t.FullName -Recurse -Force -ErrorAction SilentlyContinue
}

$left = @(Get-ChildItem -LiteralPath $logs -Force -ErrorAction SilentlyContinue)
Write-Host ''
Write-Host ("已清空，剩余 {0} 项" -f $left.Count) -ForegroundColor Green
foreach ($l in $left) { Write-Host "  残留 $($l.Name)" -ForegroundColor Yellow }
Write-Host '看板（8900）刷新即为空。' -ForegroundColor Green
