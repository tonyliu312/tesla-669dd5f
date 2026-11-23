#requires -Version 5.1
<#
hotspot_probe.ps1 — 给 WEB 看板用的探针：输出单行 JSON
  {"state":"On|Off","ssid":"...","clients":[{"mac":"..","name":".."}]}
不弹 UAC、不改配置，只读。
#>
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $task = $asTask.Invoke($null, @($WinRtTask))
    $task.Wait(15000) | Out-Null
    $task.Result
}

[Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringClient, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime] | Out-Null

$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if (-not $profile) {
    '{"state":"no-internet-profile","ssid":null,"clients":[]}'
    exit 0
}

$mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
$cfg = $mgr.GetCurrentAccessPointConfiguration()

$out = [ordered]@{
    state   = $mgr.TetheringOperationalState.ToString()
    ssid    = $cfg.Ssid
    clients = @()
}

try {
    $list = Await ($mgr.GetTetheringClientsAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Networking.NetworkOperators.NetworkOperatorTetheringClient]])
    foreach ($c in $list) {
        $name = @($c.HostNames | ForEach-Object { $_.DisplayName }) | Select-Object -First 1
        $out.clients += [ordered]@{ mac = $c.MacAddress; name = $name }
    }
} catch {
    # 拿不到客户端列表不影响状态显示
}

$out | ConvertTo-Json -Depth 4 -Compress
