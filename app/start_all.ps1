#requires -Version 5.1
<#
start_all.ps1 — 一键启动整套 FSD 拦截环境（可重复执行，幂等）

  .\start_all.ps1             # 普通运行
  .\start_all.ps1 -Status     # 只看状态，不动手

会确保：
  1) 防火墙入站放行 TCP 4567/8080/8899/443 + UDP 53（缺规则时自动提权一次）
  2) 常驻栈 svc\stack.py（DNS/proxy/reverse/web）
  3) ARP 引流 tools\arp_mitm.py（--rst-dst，把车机流量引到本机）
  4) 443 拦截 mitmdump（api-prd 反向 + fsd_mock 短路）
  5) 看板 http://127.0.0.1:8900
  6) 看门狗 tools\supervise_all.py（挂了自动拉起）
  7) 登录自启（HKCU Run，指向看门狗）
#>
[CmdletBinding()]
param([switch]$Status, [switch]$Elevated)

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$pyw  = Join-Path $root 'venv\Scripts\pythonw.exe'
$logs = Join-Path $root 'logs'
if (-not (Test-Path $logs)) { New-Item -ItemType Directory -Path $logs -Force | Out-Null }
$env:FSD_MOCK_LOG_DIR = $logs
$env:FSD_MOCK_JSON = Join-Path $root 'payload.json'
$env:FSD_MOCK_LOG_ALL = '1'
$env:FSD_MOCK_MODE_FILE = Join-Path $root 'mode.json'

function PortOpen([int]$p) {
    try { $c = New-Object System.Net.Sockets.TcpClient; $ok = $c.ConnectAsync('127.0.0.1', $p).Wait(300); $c.Dispose(); return $ok } catch { return $false }
}

function ProcCount([string]$pattern) {
    @(Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -and $_.CommandLine -match $pattern }).Count
}

function Show-Status {
    $rows = @(
        [pscustomobject]@{ 组件='常驻栈 4567';   状态=$(if (PortOpen 4567) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件='代理 8080';     状态=$(if (PortOpen 8080) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件='看板 8899';     状态=$(if (PortOpen 8899) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件='443 拦截';      状态=$(if (PortOpen 443) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件='看板 8900';     状态=$(if (PortOpen 8900) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件='ARP 引流';      状态=$(if ((ProcCount 'arp_mitm\.py') -gt 0) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件='看门狗';        状态=$(if ((ProcCount 'supervise_all\.py') -gt 0) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ 组件='防火墙规则';    状态=("{0}/5" -f @('fsd-mitm-reverse-4567','fsd-mitm-proxy-8080','fsd-mitm-dns-53','fsd-mitm-web-8899','fsd-mitm-api443' | Where-Object { Get-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue }).Count) },
        [pscustomobject]@{ 组件='登录自启';      状态=$(if ((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'fsd-mitm-supervisor' -ErrorAction SilentlyContinue)) { 'OK' } else { '无' }) }
    )
    $rows | Format-Table -AutoSize | Out-String -Width 80
}

Write-Host "`n===== FSD 拦截环境 · 一键启动 =====" -ForegroundColor Cyan

if ($Status) { Show-Status; return }

# 1) 防火墙
$rules = @(
    @{ Name='fsd-mitm-reverse-4567'; Proto='TCP'; Port=4567 },
    @{ Name='fsd-mitm-proxy-8080';   Proto='TCP'; Port=8080 },
    @{ Name='fsd-mitm-dns-53';       Proto='UDP'; Port=53 },
    @{ Name='fsd-mitm-web-8899';     Proto='TCP'; Port=8899 },
    @{ Name='fsd-mitm-api443';       Proto='TCP'; Port=443 }
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
            -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Elevated'
        Start-Sleep -Seconds 4
    }
} else { Write-Host '防火墙: 5 条规则齐全' -ForegroundColor Green }

# 2) 常驻栈
if (-not (PortOpen 4567)) {
    Write-Host '常驻栈: 启动中...' -ForegroundColor Yellow
    Start-Process -FilePath $pyw -ArgumentList (Join-Path $root 'svc\stack.py') -WindowStyle Hidden
    Start-Sleep -Seconds 10
} else { Write-Host '常驻栈: 已在运行' -ForegroundColor Green }

# 3) ARP 引流
if ((ProcCount 'arp_mitm\.py') -eq 0) {
    Write-Host 'ARP 引流: 启动中...' -ForegroundColor Yellow
    Start-Process -FilePath $pyw -WindowStyle Hidden -ArgumentList @(
        (Join-Path $root 'tools\arp_mitm.py'), '--target','192.168.199.95','--gateway','192.168.199.1',
        '--our-ip','192.168.199.148','--answer','192.168.199.148','--iface','Wi-Fi',
        '--duration','7200','--rst-dst','52.81.9.181')
    Start-Sleep -Seconds 6
} else { Write-Host 'ARP 引流: 已在运行' -ForegroundColor Green }

# 4) 443 拦截
if (-not (PortOpen 443)) {
    Write-Host '443 拦截: 启动中...' -ForegroundColor Yellow
    $a = @('-s',(Join-Path $root 'fsd_mock.py'),
           '--set',('confdir=' + (Join-Path $root 'certs2')),'--set','ssl_insecure=true',
           '--set','connection_strategy=lazy','--set','block_global=false','--emudhra',
           '--mode','reverse:https://api-prd.vn.cloud.tesla.cn@443')
    Start-Process -FilePath (Join-Path $root 'venv\Scripts\mitmdump.exe') -ArgumentList $a -WindowStyle Hidden
    Start-Sleep -Seconds 8
} else { Write-Host '443 拦截: 已在运行' -ForegroundColor Green }

# 5) 看板
if (-not (PortOpen 8900)) {
    Write-Host '看板 8900: 启动中...' -ForegroundColor Yellow
    Start-Process -FilePath $pyw -ArgumentList @((Join-Path $root 'web\fsd_panel.py'),'--port','8900') -WindowStyle Hidden
    Start-Sleep -Seconds 4
} else { Write-Host '看板 8900: 已在运行' -ForegroundColor Green }

# 6) 看门狗
if ((ProcCount 'supervise_all\.py') -eq 0) {
    Write-Host '看门狗: 启动中...' -ForegroundColor Yellow
    Start-Process -FilePath $pyw -ArgumentList (Join-Path $root 'tools\supervise_all.py') -WindowStyle Hidden
    Start-Sleep -Seconds 3
} else { Write-Host '看门狗: 已在运行' -ForegroundColor Green }

# 7) 登录自启
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$want = '"' + $pyw + '" "' + (Join-Path $root 'tools\supervise_all.py') + '"'
Set-ItemProperty -Path $runKey -Name 'fsd-mitm-supervisor' -Value $want -Type String
Write-Host '登录自启: 已确保' -ForegroundColor Green

Write-Host "`n===== 状态 =====" -ForegroundColor Cyan
Show-Status
Write-Host "看板: http://127.0.0.1:8900    填写配置: http://127.0.0.1:8900/config`n" -ForegroundColor Green