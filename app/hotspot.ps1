#requires -Version 5.1
<#
hotspot.ps1 — 用 Windows 移动热点给车机开 WiFi（不需要管理员）

  .\hotspot.ps1 -Action start
  .\hotspot.ps1 -Action start -Ssid FSD-SCORE -Key fsd2026!!
  .\hotspot.ps1 -Action status
  .\hotspot.ps1 -Action stop

注意：
  * Windows 11 用 Wi-Fi Direct（不需要"承载网络/Hosted network"），网卡不支持也能开；
  * 想给车机同时保留公网，需要在 设置→网络→移动热点 里把"共享我的以下 Internet 连接"选成上行网卡；
  * 热点网段一般是 192.168.137.0/24，本机网关 192.168.137.1 —— DNS/hosts 方案要把这个 IP 给车机。
#>
[CmdletBinding()]
param(
    [ValidateSet('start', 'stop', 'status')] [string]$Action = 'status',
    [string]$Ssid = 'FSD-SCORE',
    [string]$Key = 'fsd2026!!'
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $task = $asTask.Invoke($null, @($WinRtTask))
    if (-not $task.Wait(20000)) { throw '等待移动热点操作超时' }
    $task.Result
}

[Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime] | Out-Null

$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if (-not $profile) { throw '当前没有可用的 Internet 连接配置，先连上 Wi-Fi/以太网' }

$mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)

switch ($Action) {
    'status' {
        Write-Host ("internet profile : {0}" -f $profile.ProfileName)
        Write-Host ("tethering state  : {0}" -f $mgr.TetheringOperationalState)
        Write-Host ("ssid             : {0}" -f $mgr.GetCurrentAccessPointConfiguration().Ssid)
        Write-Host ("max clients      : {0}" -f $mgr.MaxClientCount)
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Local Area Connection|本地连接|Wi-Fi Direct' } |
            Select-Object IPAddress, InterfaceAlias | Format-Table -AutoSize | Out-String -Width 100
    }
    'start' {
        if ($mgr.TetheringOperationalState -eq 'On') {
            Write-Host '热点已经在运行' -ForegroundColor Yellow
        }
        else {
            $cfg = $mgr.GetCurrentAccessPointConfiguration()
            $cfg.Ssid = $Ssid
            $cfg.Passphrase = $Key
            $asActionTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
                $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
                $_.GetParameters()[0].ParameterType.FullName -eq 'Windows.Foundation.IAsyncAction'
            }
            $task = $asActionTask.Invoke($null, @($mgr.ConfigureAccessPointAsync($cfg)))
            if (-not $task.Wait(20000)) { throw '保存移动热点配置超时' }

            $res = Await ($mgr.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
            if ($res.Status -ne 'Success') {
                throw ("启动移动热点失败: {0} {1}" -f $res.Status, $res.AdditionalErrorMessage)
            }
        }
        Start-Sleep -Seconds 2
        if ($mgr.TetheringOperationalState -ne 'On') { throw "移动热点状态: $($mgr.TetheringOperationalState)" }
        $cfg = $mgr.GetCurrentAccessPointConfiguration()
        Write-Host ("state: {0}" -f $mgr.TetheringOperationalState)
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.137.*' } |
            Select-Object IPAddress, InterfaceAlias | Format-Table -AutoSize | Out-String -Width 100
        Write-Host ("SSID={0}  KEY={1}" -f $cfg.Ssid, $cfg.Passphrase) -ForegroundColor Green
    }
    'stop' {
        $res = Await ($mgr.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
        if ($res.Status -ne 'Success') {
            throw ("关闭移动热点失败: {0} {1}" -f $res.Status, $res.AdditionalErrorMessage)
        }
        Write-Host ("state: {0}" -f $mgr.TetheringOperationalState)
    }
}
