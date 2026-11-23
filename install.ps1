#requires -Version 5.1
<#
install.ps1 —— FSD 拦截环境（热点模式）一键安装器

  双击「一键安装.cmd」即可；或在本目录执行：

    .\install.ps1                 # 体检 → 复制 → 建 venv → 装依赖 → 快捷方式 → 自启 → 启动
    .\install.ps1 -Check          # 只体检，不动任何文件
    .\install.ps1 -SkipVenv       # 已有可用的 venv，跳过重建
    .\install.ps1 -NoStart        # 部署完不启动
    .\install.ps1 -UseMirror      # pip 走清华源（国内网络慢时用）
    .\install.ps1 -Force          # 目标已有部署时强制覆盖源码（保留 logs / venv，备份 payload.json）

安装目录固定 C:\fsd-mitm：项目里约 24 处路径是写死的（svc\stack.py、tools\supervise_all.py、
web\server.py、stop_stack.ps1 等），换盘必须逐处改，本安装器不做这种改写。
#>
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Force,
    [switch]$SkipVenv,
    [switch]$NoStart,
    [switch]$NoShortcut,
    [switch]$NoAutostart,
    [switch]$UseMirror,
    [switch]$AutoInstallPython,
    [string]$PythonExe,
    [string]$Target = 'C:\fsd-mitm'
)

$ErrorActionPreference = 'Continue'
$src = Join-Path $PSScriptRoot 'app'
$script:okCount = 0
$script:warnCount = 0
$script:failCount = 0

function Step([string]$n, [string]$t) {
    Write-Host ''
    Write-Host ("[{0}] {1}" -f $n, $t) -ForegroundColor Cyan
}
function Good([string]$m) { $script:okCount++;   Write-Host "     OK    $m" -ForegroundColor Green }
function Note([string]$m) { $script:warnCount++; Write-Host "     WARN  $m" -ForegroundColor Yellow }
function Fail([string]$m) { $script:failCount++; Write-Host "     FAIL  $m" -ForegroundColor Red }
function Info([string]$m) { Write-Host "           $m" -ForegroundColor DarkGray }

function Test-Port([int]$p) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $ok = $c.ConnectAsync('127.0.0.1', $p).Wait(250)
        $c.Dispose()
        return $ok
    } catch { return $false }
}

function Test-PythonExe([string]$Exe, [string[]]$PreArgs = @()) {
    if (-not $Exe) { return $null }
    if (-not (Test-Path -LiteralPath $Exe)) { return $null }
    # Microsoft Store 的 App Execution Alias：0 字节占位符，执行只会弹商店 —— 必须排除
    if ($Exe -match '\\WindowsApps\\') { return $null }
    try { $item = Get-Item -LiteralPath $Exe -Force -ErrorAction Stop } catch { return $null }
    if ($item.Length -eq 0) { return $null }
    try {
        $raw = & $Exe @PreArgs -c "import sys;print('%d.%d' % sys.version_info[:2])" 2>$null
    } catch { return $null }
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
    $v = "$(@($raw) | Select-Object -First 1)".Trim()
    if ($v -notmatch '^(\d+)\.(\d+)$') { return $null }
    $maj = [int]$Matches[1]; $min = [int]$Matches[2]
    if ($maj -lt 3 -or ($maj -eq 3 -and $min -lt 10)) { return $null }
    return [pscustomobject]@{ Exe = $Exe; Pre = $PreArgs; Version = $v; Via = '' }
}

function Find-Python {
    # 1) 用户显式指定
    if ($PythonExe) {
        $c = Test-PythonExe $PythonExe
        if ($c) { $c.Via = '-PythonExe'; return $c }
        Note "指定的 Python 不可用：$PythonExe"
    }
    # 2) PATH（Store 占位符会被 Test-PythonExe 拒掉）
    foreach ($n in @('python', 'python3')) {
        $cmd = Get-Command $n -ErrorAction SilentlyContinue
        if ($cmd) {
            $c = Test-PythonExe $cmd.Source
            if ($c) { $c.Via = "PATH ($n)"; return $c }
        }
    }
    # 3) py 启动器
    $pyCmd = Get-Command 'py' -ErrorAction SilentlyContinue
    if ($pyCmd) {
        foreach ($v in @('3.12', '3.11', '3.13', '3')) {
            $c = Test-PythonExe $pyCmd.Source @("-$v")
            if ($c) { $c.Via = "py -$v"; return $c }
        }
    }
    # 4) 标准安装目录
    foreach ($pat in @(
            "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
            "C:\Python3*\python.exe",
            "$env:ProgramFiles\Python3*\python.exe",
            "${env:ProgramFiles(x86)}\Python3*\python.exe")) {
        foreach ($f in @(Get-ChildItem $pat -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
            $c = Test-PythonExe $f.FullName
            if ($c) { $c.Via = '安装目录'; return $c }
        }
    }
    # 5) 注册表
    foreach ($hive in @('HKLM:\SOFTWARE\Python\PythonCore',
                        'HKCU:\SOFTWARE\Python\PythonCore',
                        'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore')) {
        foreach ($k in @(Get-ChildItem $hive -ErrorAction SilentlyContinue | Sort-Object PSChildName -Descending)) {
            $ip = (Get-ItemProperty (Join-Path $k.PSPath 'InstallPath') -ErrorAction SilentlyContinue).'(default)'
            if ($ip) {
                $c = Test-PythonExe (Join-Path $ip 'python.exe')
                if ($c) { $c.Via = '注册表'; return $c }
            }
        }
    }
    # 6) 随附 / 便携运行时（如 DSH 自带的 Python）
    foreach ($g in @("$env:USERPROFILE\.dsh\dsh-runtimes\*\dependencies\python\python.exe",
                     "$env:LOCALAPPDATA\dsh\dsh-runtimes\*\dependencies\python\python.exe")) {
        foreach ($f in @(Get-ChildItem $g -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
            $c = Test-PythonExe $f.FullName
            if ($c) { $c.Via = '随附运行时'; return $c }
        }
    }
    # 7) 现有 venv 的 base（pyvenv.cfg 里的 home）
    $cfg = Join-Path $Target 'venv\pyvenv.cfg'
    if (Test-Path $cfg) {
        $line = @(Get-Content $cfg | Where-Object { $_ -match '^\s*home\s*=' })
        if ($line.Count -gt 0) {
            $homePath = (($line[0] -split '=', 2)[1]).Trim()
            $c = Test-PythonExe (Join-Path $homePath 'python.exe')
            if ($c) { $c.Via = '现有 venv 的 base'; return $c }
        }
    }
    return $null
}

# ---------------------------------------------------------------- 头部
Write-Host ''
Write-Host '  ============================================' -ForegroundColor White
Write-Host '   FSD 拦截环境' -ForegroundColor White
Write-Host '   ============================================' -ForegroundColor White
Write-Host ("   包位置 : {0}" -f $PSScriptRoot) -ForegroundColor DarkGray
Write-Host ("   安装到 : {0}" -f $Target) -ForegroundColor DarkGray
if ($Check) { Write-Host '   模式   : 只体检（不改动任何文件）' -ForegroundColor DarkGray }

$transcript = $null
if (-not $Check) {
    try {
        $logDir = Join-Path $Target 'logs'
        if (Test-Path $logDir) {
            $transcript = Join-Path $logDir ('install-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            Start-Transcript -Path $transcript -Force | Out-Null
        }
    } catch { }
}

try {

# ---------------------------------------------------------------- 0 环境
Step '0/7' '运行环境'
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Fail ("PowerShell 版本过低：{0}（需 5.1+）" -f $PSVersionTable.PSVersion)
    exit 1
}
Good ("PowerShell {0}" -f $PSVersionTable.PSVersion)
if (-not [Environment]::Is64BitOperatingSystem) {
    Fail '需要 64 位 Windows'
} else {
    Good 'Windows x64'
}
if (-not (Test-Path (Join-Path $src 'start_all.ps1'))) {
    Fail "安装源不完整：缺少 $src\start_all.ps1"
    Fail '请把整个压缩包解压后再运行，不要只拷出安装脚本。'
    exit 1
}
Good ("安装源完整：app\ 共 {0} 个文件" -f (Get-ChildItem $src -Recurse -File).Count)

# ---------------------------------------------------------------- 1 目标
Step '1/7' '安装目录检查'
$canonical = 'C:\fsd-mitm'
if ($Target.TrimEnd('\') -ne $canonical) {
    Fail ("安装目录必须是 {0}" -f $canonical)
    Info '项目内约 24 处路径写死（svc\stack.py / tools\supervise_all.py / web\server.py / stop_stack.ps1 …），'
    Info '换盘需要先逐处改源码，本安装器不做自动改写。'
    exit 2
}
$existing = Test-Path (Join-Path $Target 'start_all.ps1')
if ($existing) {
    Note "目标目录已有部署：$Target"
    Info '按覆盖安装处理：覆盖源码，保留 logs\ 与 venv\，payload.json 自动备份。'
    if ($Check) { Info '（-Check 模式不改动任何文件）' }
} else {
    Good '目标目录为空或不存在（全新安装）'
}

$busy = @()
foreach ($p in @(443, 4567, 8080, 8899, 8900)) {
    if (Test-Port $p) { $busy += $p }
}
if ($busy.Count -gt 0) {
    Note ("以下端口已有监听：{0}" -f (($busy | Sort-Object) -join ', '))
    Info '说明有一套实例正在运行。覆盖源码不影响已加载的进程（重启后生效）；'
    Info '若要先停：C:\fsd-mitm\stop_hotspot.ps1（热点模式）或 C:\fsd-mitm\stop_fsd_all.ps1（路由模式）'
} else {
    Good '相关端口空闲（443 / 4567 / 8080 / 8899 / 8900）'
}

if ($Check) {
    Write-Host ''
    Write-Host '  ===== 体检结果（未做任何改动） =====' -ForegroundColor Cyan
    $items = @(
        @{ N = 'pythonw.exe';       P = (Join-Path $Target 'venv\Scripts\pythonw.exe') },
        @{ N = 'mitmdump.exe';      P = (Join-Path $Target 'venv\Scripts\mitmdump.exe') },
        @{ N = 'CA (certs2)';       P = (Join-Path $Target 'certs2\mitmproxy-ca.pem') },
        @{ N = 'payload.json';      P = (Join-Path $Target 'payload.json') },
        @{ N = 'start_hotspot.ps1'; P = (Join-Path $Target 'start_hotspot.ps1') },
        @{ N = 'stop_hotspot.ps1';  P = (Join-Path $Target 'stop_hotspot.ps1') },
        @{ N = 'start_all.ps1';     P = (Join-Path $Target 'start_all.ps1') },
        @{ N = 'stop_fsd_all.ps1';  P = (Join-Path $Target 'stop_fsd_all.ps1') },
        @{ N = 'tools\arp_mitm.py'; P = (Join-Path $Target 'tools\arp_mitm.py') },
        @{ N = 'web\fsd_panel.py';  P = (Join-Path $Target 'web\fsd_panel.py') }
    )
    foreach ($i in $items) {
        if (Test-Path $i.P) { Good $i.N } else { Fail $i.N }
    }
    # Python 解释器探测：venv 已就绪时不需要系统 Python
    $venvPywCheck = Join-Path $Target 'venv\Scripts\pythonw.exe'
    $probe = Find-Python
    if ($probe) {
        Good ("Python {0}（来源：{1}）" -f $probe.Version, $probe.Via)
    } elseif (Test-Path $venvPywCheck) {
        Good 'Python：venv 已就绪（不依赖系统 Python）'
    } else {
        Fail 'Python 3.10+：未找到（去掉 -Check 后加 -AutoInstallPython 重跑）'
    }
    $pl = Join-Path $Target 'payload.json'
    if (Test-Path $pl) {
        try {
            $txt = (Get-Content -LiteralPath $pl -Raw).Trim()
            $obj = $txt | ConvertFrom-Json
            $n = @($obj.PSObject.Properties).Count
            Good ("payload.json 合法：{0} 字节 / {1} 字段" -f (Get-Item $pl).Length, $n)
        } catch { Fail 'payload.json 不是合法 JSON' }
    }
    Write-Host ''
    Write-Host ("  OK={0} WARN={1} FAIL={2}" -f $script:okCount, $script:warnCount, $script:failCount) -ForegroundColor $(if ($script:failCount) { 'Red' } else { 'Green' })
    if ($script:failCount -eq 0) {
        Write-Host '  依赖齐全，可运行：C:\fsd-mitm\start_all.cmd' -ForegroundColor Green
    } else {
        Write-Host '  缺失项在上表，去掉 -Check 重新运行即可补齐。' -ForegroundColor Yellow
    }
    exit $(if ($script:failCount) { 1 } else { 0 })
}

# ---------------------------------------------------------------- 2 复制
Step '2/7' '复制程序文件'
New-Item -ItemType Directory -Path $Target -Force | Out-Null
$plTarget = Join-Path $Target 'payload.json'
if (Test-Path $plTarget) {
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    Copy-Item -LiteralPath $plTarget -Destination ("{0}.preinstall-{1}" -f $plTarget, $ts) -Force
    Info ("已备份原载荷：payload.json.preinstall-{0}" -f $ts)
}
$rc = robocopy $src $Target /E /NFL /NDL /NJH /NJS /NP /XD 'logs' 'venv' 'backup' '__pycache__' /XF '*.pyc'
if ($LASTEXITCODE -ge 8) {
    Fail ("robocopy 失败，退出码 {0}" -f $LASTEXITCODE)
    exit 3
}
Good ("已复制 {0} 个文件（logs / venv 未被覆盖）" -f (Get-ChildItem $src -Recurse -File).Count)

# ---------------------------------------------------------------- 3 venv
Step '3/7' 'Python 虚拟环境'
$venvDir = Join-Path $Target 'venv'
$venvPy  = Join-Path $venvDir 'Scripts\python.exe'
$venvPyw = Join-Path $venvDir 'Scripts\pythonw.exe'
$venvMit = Join-Path $venvDir 'Scripts\mitmdump.exe'
$req     = Join-Path $Target 'requirements.txt'

if ($SkipVenv) {
    Note '已跳过 venv（-SkipVenv）'
} elseif ((Test-Path $venvMit) -and (Test-Path $venvPyw)) {
    Good 'venv 已就绪（mitmdump.exe / pythonw.exe 存在）'
} else {
    if (Test-Path $venvDir) {
        $bak = "$venvDir.broken-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Move-Item -LiteralPath $venvDir -Destination $bak -Force
        Note ("原 venv 不完整，已改名为 {0}" -f (Split-Path $bak -Leaf))
    }
    $py = Find-Python
    if (-not $py -and $AutoInstallPython) {
        $winget = Get-Command 'winget' -ErrorAction SilentlyContinue
        if ($winget) {
            Info '未找到 Python，改用 winget 安装 3.12（会弹 UAC、需要网络）…'
            & $winget.Source install --id Python.Python.3.12 -e --silent `
                --accept-package-agreements --accept-source-agreements
            $py = Find-Python
        } else {
            Note '本机没有 winget，无法自动安装 Python'
        }
    }
    if (-not $py) {
        Fail '找不到可用的 Python 3.10+'
        Info '已尝试：-PythonExe → PATH → py 启动器 → 常见安装目录 → 注册表 → 随附运行时 → 现有 venv 的 base'
        Info '（PATH 里 WindowsApps\python.exe 是应用商店占位符，已自动跳过，不是真 Python）'
        Info ''
        Info '四选一：'
        Info '  1) 自动装：  .\install.ps1 -AutoInstallPython'
        Info '  2) 手动装：  winget install Python.Python.3.12'
        Info '             或 https://www.python.org/downloads/windows/ （勾 Add to PATH）'
        Info '  3) 指定路径：.\install.ps1 -PythonExe "C:\Path\python.exe"'
        Info '  4) 免 Python：把另一台机器的 venv 拷到 C:\fsd-mitm\venv（路径必须一致），再 .\install.ps1 -SkipVenv'
        exit 4
    }
    Good ("使用 Python {0}（来源：{1}）" -f $py.Version, $py.Via)
    Info ("解释器：{0} {1}" -f $py.Exe, ($py.Pre -join ' '))
    Info '创建 venv …'
    & $py.Exe @($py.Pre) -m venv $venvDir
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $venvPy)) {
        Fail 'venv 创建失败'
        exit 4
    }
    Good 'venv 已创建'

    $pip = Join-Path $venvDir 'Scripts\pip.exe'
    $pipArgs = @('install', '--disable-pip-version-check', '--no-input', '-r', $req)
    if ($UseMirror) {
        $pipArgs += @('-i', 'https://pypi.tuna.tsinghua.edu.cn/simple',
                      '--trusted-host', 'pypi.tuna.tsinghua.edu.cn')
        Info 'pip 使用清华镜像'
    }
    Info '安装依赖（mitmproxy 12.3.1 / scapy / flask / cryptography），首次约 2–5 分钟 …'
    if (Test-Path $pip) {
        & $pip @pipArgs
    } else {
        & $venvPy -m pip @pipArgs
    }
    if ($LASTEXITCODE -ne 0) {
        Fail ("pip 安装失败（退出码 {0}）" -f $LASTEXITCODE)
        Info '网络问题可重试：.\install.ps1 -UseMirror -SkipVenv'
        exit 4
    }
    if (-not (Test-Path $venvMit)) {
        Fail '依赖装完但没有 mitmdump.exe，venv 异常'
        exit 4
    }
    Good '依赖安装完成（mitmdump.exe 就绪）'
}

# ---------------------------------------------------------------- 4 体检
Step '4/7' '关键文件体检'
$checks = @(
    @{ N = 'venv\Scripts\pythonw.exe';   P = $venvPyw },
    @{ N = 'venv\Scripts\mitmdump.exe';  P = $venvMit },
    @{ N = 'certs2\mitmproxy-ca.pem';    P = (Join-Path $Target 'certs2\mitmproxy-ca.pem') },
    @{ N = 'payload.json';               P = $plTarget },
    @{ N = 'fsd_mock.py';                P = (Join-Path $Target 'fsd_mock.py') },
    @{ N = 'start_hotspot.ps1';          P = (Join-Path $Target 'start_hotspot.ps1') },
    @{ N = 'stop_hotspot.ps1';           P = (Join-Path $Target 'stop_hotspot.ps1') },
    @{ N = 'dns_sink.py';                P = (Join-Path $Target 'dns_sink.py') },
    @{ N = 'start_all.ps1';              P = (Join-Path $Target 'start_all.ps1') },
    @{ N = 'stop_fsd_all.ps1';           P = (Join-Path $Target 'stop_fsd_all.ps1') },
    @{ N = 'tools\arp_mitm.py';          P = (Join-Path $Target 'tools\arp_mitm.py') },
    @{ N = 'tools\supervise_all.py';     P = (Join-Path $Target 'tools\supervise_all.py') },
    @{ N = 'web\fsd_panel.py';           P = (Join-Path $Target 'web\fsd_panel.py') }
)
foreach ($c in $checks) {
    if (Test-Path $c.P) { Good $c.N } else { Fail $c.N }
}
if (Test-Path $plTarget) {
    try {
        $txt = (Get-Content -LiteralPath $plTarget -Raw).Trim()
        $null = $txt | ConvertFrom-Json
        Good ("payload.json 合法：{0} 字节" -f (Get-Item $plTarget).Length)
    } catch { Fail 'payload.json 不是合法 JSON' }
}

# ---------------------------------------------------------------- 5 快捷方式
Step '5/7' '桌面快捷方式'
if ($NoShortcut) {
    Note '已跳过（-NoShortcut）'
} else {
    try {
        $ws = New-Object -ComObject WScript.Shell
        $desktop = [Environment]::GetFolderPath('Desktop')

        $l1 = $ws.CreateShortcut((Join-Path $desktop 'FSD一键启动.lnk'))
        $l1.TargetPath = Join-Path $Target 'start_hotspot.cmd'
        $l1.WorkingDirectory = $Target
        $l1.IconLocation = 'C:\Windows\System32\shell32.dll,137'
        $l1.Description = '一键启动 FSD 拦截环境（热点模式：443 拦截 + DNS 劫持 + 看板）'
        $l1.Save()

        $l2 = $ws.CreateShortcut((Join-Path $desktop 'FSD一键停止.lnk'))
        $l2.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $l2.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $Target 'stop_hotspot.ps1') + '" -NoExit'
        $l2.WorkingDirectory = $Target
        $l2.IconLocation = 'C:\Windows\System32\shell32.dll,131'
        $l2.Description = '停止 FSD 拦截环境（热点模式三个组件）'
        $l2.Save()

        Good 'FSD一键启动 / FSD一键停止 已创建'
    } catch {
        Fail ("快捷方式创建失败：{0}" -f $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- 6 自启
Step '6/7' '登录自启（看门狗）'
if ($NoAutostart) {
    Note '已跳过（-NoAutostart）'
} else {
    try {
        $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
        $val = '"' + (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') + '" ' +
               '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' +
               (Join-Path $Target 'start_hotspot.ps1') + '" -NoFirewall'
        Set-ItemProperty -Path $runKey -Name 'fsd-mitm-supervisor' -Value $val -Type String
        Good 'HKCU\Run\fsd-mitm-supervisor 已写入（热点模式启动）'
    } catch {
        Fail ("自启写入失败：{0}" -f $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- 7 启动
Step '7/7' '启动'
if ($NoStart) {
    Note '已跳过启动（-NoStart）'
} else {
    if ($script:failCount -gt 0) {
        Note '前面有 FAIL 项，跳过启动。修好后执行：C:\fsd-mitm\start_hotspot.cmd'
    } else {
        Info '启动中（首次会弹一次 UAC 补防火墙规则，请点“是”）…'
        & (Join-Path $Target 'start_hotspot.ps1')
    }
}

# ---------------------------------------------------------------- 汇总
Write-Host ''
Write-Host '  ============================================' -ForegroundColor White
Write-Host ("   结果：OK={0} WARN={1} FAIL={2}" -f $script:okCount, $script:warnCount, $script:failCount) -ForegroundColor $(if ($script:failCount) { 'Red' } else { 'Green' })
Write-Host '  ============================================' -ForegroundColor White
Write-Host ("   看板      : http://127.0.0.1:8900") -ForegroundColor White
Write-Host ("   载荷编辑  : http://127.0.0.1:8900/payload") -ForegroundColor White
Write-Host ("   启动      : {0}\start_hotspot.cmd   （热点模式）" -f $Target) -ForegroundColor DarkGray
Write-Host ("   状态      : powershell -File {0}\start_hotspot.ps1 -Status" -f $Target) -ForegroundColor DarkGray
Write-Host ("   停止      : powershell -File {0}\stop_hotspot.ps1" -f $Target) -ForegroundColor DarkGray
Write-Host ("   路由模式  : {0}\start_all.cmd（车机与电脑连同一路由器时用）" -f $Target) -ForegroundColor DarkGray
Write-Host ("   只撤拦截  : powershell -File {0}\stop_api_intercept.ps1" -f $Target) -ForegroundColor DarkGray
Write-Host ''

} finally {
    if ($transcript) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}

exit $(if ($script:failCount) { 1 } else { 0 })
