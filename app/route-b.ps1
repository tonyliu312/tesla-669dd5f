#requires -Version 5.1
<#
route-b.ps1 — 使用 Windows 移动热点建立 PC 与车机的 Wi-Fi 链路

  .\route-b.ps1                 # 开热点，共享 Windows 当前的 Internet 连接
  .\route-b.ps1 -Stop           # 关闭移动热点
  .\route-b.ps1 -Ssid FSD-PC -Key fsd2026!! -NoShare

Windows 移动热点使用当前的 Internet 连接作为上行。
保留 -NoShare 参数以兼容原来的调用。上行共享由 Windows 管理。
#>
[CmdletBinding()]
param(
    [string]$Ssid = 'FSD-PC',
    [string]$Key = 'fsd2026!!',
    [switch]$NoShare,
    [switch]$Stop
)

$ErrorActionPreference = 'Stop'
$shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$hotspot = Join-Path $PSScriptRoot 'hotspot.ps1'
$action = if ($Stop) { 'stop' } else { 'start' }
& $shell -NoProfile -ExecutionPolicy Bypass -File $hotspot -Action $action -Ssid $Ssid -Key $Key
if ($LASTEXITCODE -ne 0) { throw "移动热点操作失败 (exit $LASTEXITCODE)" }
