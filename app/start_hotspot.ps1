#requires -Version 5.1
<#
start_hotspot.ps1 — 热点模式一键启动（默认链路）

  手机 USB 共享网络 → 电脑开热点 FSD-PC → 车机连 FSD-PC
  车机网关/DNS 都是本机 192.168.137.1，电脑本身就是网关，所以不做 ARP 投毒。

  .\start_hotspot.ps1                  # 启动 443 拦截 + DNS 劫持 + 看板 8900
  .\start_hotspot.ps1 -Status          # 只看状态，不动手
  .\start_hotspot.ps1 -OurIp 192.168.137.1

路由模式（车机与电脑连同一台路由器）请改用 start_all.cmd。
#>
[CmdletBinding()]
param([switch]$Status, [switch]$Elevated, [switch]$NoFirewall, [string]$OurIp = '192.168.137.1')

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$logs = Join-Path $root 'logs'
if (-not (Test-Path $logs)) { New-Item -ItemType Directory -Path $logs -Force | Out-Null }

$mitm = Join-Path $root 'venv\Scripts\mitmdump.exe'
$py   = Join-Path $root 'venv\Scripts\python.exe'
$pyw  = Join-Path $root 'venv\Scripts\pythonw.exe'

function PortOpen([int]$p) {
    try { $c = New-Object System.Net.Sockets.TcpClient; $ok = $c.ConnectAsync('127.0.0.1', $p).Wait(300); $c.Dispose(); return $ok } catch { return $false }
}

function ProcCount([string]$pattern) {
    @(Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -and $_.CommandLine -match $pattern }).Count
}

function HotspotIpUp {
    [bool](Get-NetIPAddress -IPAddress $OurIp -ErrorAction SilentlyContinue)
}

function CarSeen {
    @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -like '192.168.137.*' -and $_.IPAddress -ne $OurIp -and $_.State -ne 'Unreachable' }).Count -gt 0
}

function Show-Status {
    $rows = @(
        [pscustomobject]@{ 组件='443 拦截';  状态=$(if (PortOpen 443) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件='DNS 53';    状态=$(if ((ProcCount 'dns_sink\.py') -gt 0) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件='看板 8900'; 状态=$(if (PortOpen 8900) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件="热点 $OurIp"; 状态=$(if (HotspotIpUp) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件='车机在线';  状态=$(if (CarSeen) { 'OK' } else { '未见' }) }
    )
    $rows | Format-Table -AutoSize | Out-String -Width 80
}

Write-Host "`n===== FSD 拦截环境 · 热点模式 =====" -ForegroundColor Cyan

if ($Status) { Show-Status; return }

# 1) 防火墙（443 TCP / 53 UDP 入站）
if ($NoFirewall) {
    Write-Host '防火墙: 已跳过（-NoFirewall）' -ForegroundColor DarkGray
} else {
$rules = @(
    @{ Name='fsd-mitm-api443'; Proto='TCP'; Port=443 },
    @{ Name='fsd-mitm-dns-53'; Proto='UDP'; Port=53 }
)
$missing = @($rules | Where-Object { -not (Get-NetFirewallRule -DisplayName $_.Name -ErrorAction SilentlyContinue) })
if ($missing.Count -gt 0) {
    if ($Elevated) {
        foreach ($r in $missing) {
            New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Action Allow -Protocol $r.Proto -LocalPort $r.Port -Profile Any -Description 'FSD lab' -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Host ("防火墙: 已补 {0} 条规则" -f $missing.Count) -ForegroundColor Green
    } else {
        Write-Host ("防火墙: 缺 {0} 条规则，正在提权补（请点 UAC）..." -f $missing.Count) -ForegroundColor Yellow
        Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs `
            -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Elevated' | Out-Null
        Start-Sleep -Seconds 4
    }
} else { Write-Host '防火墙: 规则齐全' -ForegroundColor Green }
}

# 2) 热点检查（不自动开，提示用户）
if (HotspotIpUp) {
    Write-Host "热点: $OurIp 在线" -ForegroundColor Green
} else {
    Write-Host "热点: 没有 $OurIp —— 先开热点（手机 USB 共享网络 + 下面这条命令）" -ForegroundColor Yellow
    Write-Host '      C:\fsd-mitm\route-b.ps1 -Ssid FSD-PC -Key fsd2026!!' -ForegroundColor Yellow
}

# 3) 443 反向拦截
if (-not (PortOpen 443)) {
    Write-Host '443 拦截: 启动中...' -ForegroundColor Yellow
    $env:FSD_MOCK_JSON      = Join-Path $root 'payload.json'
    $env:FSD_MOCK_LOG_DIR   = $logs
    $env:FSD_MOCK_LOG_ALL   = '1'
    $env:FSD_MOCK_MODE_FILE = Join-Path $root 'mode.json'
    $a = @('-s',(Join-Path $root 'fsd_mock.py'),
           '--set',('confdir=' + (Join-Path $root 'certs2')),'--set','ssl_insecure=true',
           '--set','connection_strategy=lazy','--set','block_global=false','--emudhra',
           '--mode','reverse:https://api-prd.vn.cloud.tesla.cn@443')
    Start-Process -FilePath $mitm -ArgumentList $a -WindowStyle Hidden
    Start-Sleep -Seconds 8
} else { Write-Host '443 拦截: 已在运行' -ForegroundColor Green }

# 4) DNS 劫持（UDP 53，没有 TCP 监听可探，按进程判活）
if ((ProcCount 'dns_sink\.py') -eq 0) {
    Write-Host 'DNS 53: 启动中...' -ForegroundColor Yellow
    Start-Process -FilePath $py -WindowStyle Hidden -ArgumentList @(
        (Join-Path $root 'dns_sink.py'), '--ip', $OurIp, '--redirect', 'api-prd.vn.cloud.tesla.cn')
    Start-Sleep -Seconds 3
    if ((ProcCount 'dns_sink\.py') -eq 0) {
        Write-Host 'DNS 53: 起不来 —— 多半是 53 被别的进程占着（热点 DNS 代理常见），查 netstat -ano | findstr ":53 "' -ForegroundColor Red
    }
} else { Write-Host 'DNS 53: 已在运行' -ForegroundColor Green }

# 5) 看板
if (-not (PortOpen 8900)) {
    Write-Host '看板 8900: 启动中...' -ForegroundColor Yellow
    Start-Process -FilePath $pyw -ArgumentList @((Join-Path $root 'web\fsd_panel.py'),'--port','8900') -WindowStyle Hidden
    Start-Sleep -Seconds 3
} else { Write-Host '看板 8900: 已在运行' -ForegroundColor Green }

Write-Host "`n===== 状态 =====" -ForegroundColor Cyan
Show-Status
Write-Host "看板:   http://127.0.0.1:8900" -ForegroundColor Green
Write-Host "配置:   http://127.0.0.1:8900/config" -ForegroundColor Green
Write-Host "停止:   C:\fsd-mitm\stop_hotspot.cmd`n" -ForegroundColor DarkGray
