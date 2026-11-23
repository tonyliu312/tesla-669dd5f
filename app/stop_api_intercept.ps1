#requires -Version 5.1
<#
stop_api_intercept.ps1 — 一键撤销 api-prd 拦截，让车机 API 立刻恢复正常

  .\stop_api_intercept.ps1            # 真正执行
  .\stop_api_intercept.ps1 -DryRun    # 只列出会杀哪些进程，不动手

做的事：
  1) 重启 ARP 引流（带 --no-api，不再把 api-prd 应答到本机）—— 先保证车机不断网
  2) 停 443 上的 mitmproxy 反向拦截实例
  3) 删除防火墙规则 fsd-mitm-api443（需要管理员，自动提权一次）
  4) 复核：443 是否已释放、引流是否在跑

注意：不解除 ARP 引流本身（车机仍经本机出网，只是不再拦 api-prd）。
      连引流一起停：& C:\fsd-mitm\svc\stop_stack.ps1
#>
[CmdletBinding()]
param([switch]$DryRun)

$ErrorActionPreference = 'Continue'
$root  = $PSScriptRoot                     # 本脚本就在 C:\fsd-mitm 下
$pyw   = Join-Path $root 'venv\Scripts\pythonw.exe'
$entry = Join-Path $root 'tools\arp_mitm.py'
$log   = Join-Path $root 'logs\stop_api_intercept.log'

function Log($m) {
    $line = "{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $line
    if (-not $DryRun) {
        $dir = Split-Path -Parent $log
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Add-Content -LiteralPath $log -Value $line -Encoding UTF8
    }
}

Log ('=== 撤销 api-prd 拦截 ===' + $(if ($DryRun) { ' [DryRun]' } else { '' }))

# 只匹配"解释器/stub 自己"，排除 pwsh / cmd / DSH 宿主（它们的命令行里也含这些字符串）
$selfNames = @('powershell.exe','pwsh.exe','cmd.exe','DeepSeek Harness.exe')
function Get-Targets([string]$pattern, [string]$nameFilter) {
    @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like $nameFilter -and
        $selfNames -notcontains $_.Name -and
        $_.CommandLine -and $_.CommandLine -match $pattern
    })
}

# 1) 先起引流（--no-api），保证车机不断网
$arp = Get-Targets 'arp_mitm\.py' 'python*.exe'
foreach ($pr in $arp) {
    if ($DryRun) { Log ("[dry] 会停 arp_mitm pid={0}" -f $pr.ProcessId) }
    else { Stop-Process -Id $pr.ProcessId -Force -ErrorAction SilentlyContinue; Log ("停 arp_mitm pid={0}" -f $pr.ProcessId) }
}
if (-not $DryRun) {
    Start-Sleep -Seconds 2
    $a = @($entry,'--target','192.168.199.95','--gateway','192.168.199.1',
           '--our-ip','192.168.199.148','--answer','192.168.199.148',
           '--iface','Wi-Fi','--duration','7200','--no-api')
    Start-Process -FilePath $pyw -ArgumentList $a -WindowStyle Hidden
    Start-Sleep -Seconds 4
    $n = @(Get-Targets 'arp_mitm\.py' 'python*.exe').Count
    if ($n -ge 1) { Log ("引流已重启（{0} 个进程），api-prd 不再被劫持" -f $n) }
    else { Log 'ERROR: 引流没起来，车机会断网！请立即执行 start 命令' }
}

# 2) 停 443 拦截实例
$mm = Get-Targets 'mitmdump' 'python*.exe'
foreach ($pr in $mm) {
    if ($pr.CommandLine -notmatch '@443') { continue }
    if ($DryRun) { Log ("[dry] 会停 mitm443 pid={0}" -f $pr.ProcessId) }
    else { Stop-Process -Id $pr.ProcessId -Force -ErrorAction SilentlyContinue; Log ("停 mitm443 pid={0}" -f $pr.ProcessId) }
}
if (@($mm | Where-Object { $_.CommandLine -match '@443' }).Count -eq 0) { Log '443 拦截实例未在运行' }

# 3) 删防火墙规则
$rule = Get-NetFirewallRule -DisplayName 'fsd-mitm-api443' -ErrorAction SilentlyContinue
if ($rule) {
    if ($DryRun) { Log '[dry] 会删除防火墙规则 fsd-mitm-api443' }
    elseif (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Remove-NetFirewallRule -DisplayName 'fsd-mitm-api443' -ErrorAction SilentlyContinue
        Log '防火墙规则 fsd-mitm-api443 已删除'
    } else {
        Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs `
            -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',"Remove-NetFirewallRule -DisplayName 'fsd-mitm-api443' -ErrorAction SilentlyContinue"
        Log '已请求提权删除防火墙规则（请确认 UAC）'
    }
} else { Log '防火墙规则不存在（已清理过）' }

if (-not $DryRun) {
    Start-Sleep -Seconds 4
    Log '--- 复核 ---'
    Log ("443 监听数 = {0}（应为 0）" -f @(Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue).Count)
    Log ("arp_mitm 进程 = {0}（应为 2）" -f @(Get-Targets 'arp_mitm\.py' 'python*.exe').Count)
    Log '=== 完成：车机 API 约 1 分钟内恢复直连 ==='
}