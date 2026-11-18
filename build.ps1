#Requires -Version 5.1
<#
.SYNOPSIS
Builds the Network Analyser Windows zip from a clean checkout (ticket #44, decision #32).

.DESCRIPTION
Runs the release gates in order and stops at the first failure:
  1. The checkout is clean: no uncommitted or untracked files.
  2. The interpreter is the exact python.org CPython patch pinned in .python-version:
     Authenticode-signed by the Python Software Foundation, 64-bit, not free-threaded,
     not a virtual environment. uv's own Python (unsigned) is refused.
  3. uv sync --locked --no-build into a fresh build\venv made from that interpreter.
  4. The security tests (pytest -m security).
  5. The licence check, which writes THIRD-PARTY-NOTICES.txt.
  6. PyInstaller --onedir --noupx (scripts\network_analyser.spec), with LGPL packages
     such as Paramiko kept as plain .py files, and a version resource equal to --version.
  7. The zip and SHA256SUMS.txt in dist\.
It prints the commit and version it built, so that exact commit can be tagged later.
A zip over 100 MB or a first start over 5 s is a warning, not a failure. The build is
unsigned in v1 (decision #32).

.PARAMETER Python
Full path to python.exe of the pinned python.org CPython. By default the script finds it
through the Windows registry (PEP 514), then through the py launcher.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Python "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe"
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'A console build script: every message is for the operator, not the pipeline.')]
[CmdletBinding()]
param(
    [string]$Python = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$RepoRoot = $PSScriptRoot
$ZipSizeWarningBytes = 100MB
$StartWarningSeconds = 5
$Warnings = New-Object -TypeName System.Collections.Generic.List[string]

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host ''
    Write-Host "== $Text" -ForegroundColor Cyan
}

function Write-BuildWarning {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "WARNING: $Text" -ForegroundColor Yellow
    $Warnings.Add($Text)
}

function Invoke-Checked {
    # Runs a program, letting its output through to the console, and throws if it fails.
    param(
        [Parameter(Mandatory = $true)][string]$What,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )
    # Windows PowerShell 5.1 can turn a program's stderr into errors; only the exit code counts.
    $ErrorActionPreference = 'Continue'
    & $FilePath @ArgumentList | Out-Host
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "$What failed (exit code $code)."
    }
}

function Get-NativeOutput {
    # Runs a program and returns its stdout lines; throws if it fails.
    param(
        [Parameter(Mandatory = $true)][string]$What,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )
    $ErrorActionPreference = 'Continue'
    $output = @(& $FilePath @ArgumentList)
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "$What failed (exit code $code)."
    }
    return $output
}

function Find-RegisteredPython {
    # PEP 514: python.org installers register under SOFTWARE\Python\PythonCore\<tag>.
    param([Parameter(Mandatory = $true)][string]$Tag)
    $hives = @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine)
    foreach ($hive in $hives) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
        try {
            $key = $base.OpenSubKey("SOFTWARE\Python\PythonCore\$Tag\InstallPath")
            if ($null -eq $key) {
                continue
            }
            try {
                $exe = [string]$key.GetValue('ExecutablePath')
                if (-not $exe) {
                    $folder = [string]$key.GetValue('')
                    if ($folder) {
                        $exe = Join-Path -Path $folder -ChildPath 'python.exe'
                    }
                }
                if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
                    return $exe
                }
            }
            finally {
                $key.Dispose()
            }
        }
        finally {
            $base.Dispose()
        }
    }
    return $null
}

function Find-LauncherPython {
    # The py launcher (classic or the Python install manager) knows -V:<tag>.
    param([Parameter(Mandatory = $true)][string]$Tag)
    if ($null -eq (Get-Command -Name 'py' -ErrorAction SilentlyContinue)) {
        return $null
    }
    try {
        $lines = @(Get-NativeOutput -What 'py launcher' -FilePath 'py' -ArgumentList @("-V:$Tag", '-c', 'import sys; print(sys.executable)'))
    }
    catch {
        return $null
    }
    if ($lines.Count -ge 1 -and (Test-Path -LiteralPath $lines[-1] -PathType Leaf)) {
        return [string]$lines[-1]
    }
    return $null
}

function Assert-PsfSigned {
    # python.org binaries carry a valid Authenticode signature from the Python Software
    # Foundation; uv's python-build-standalone binaries are unsigned.
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Path does not exist."
    }
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "$Path is not validly signed (status: $($signature.Status)). Only a python.org CPython is accepted, never uv's own Python."
    }
    $subject = $signature.SignerCertificate.Subject
    if ($subject -notmatch '(^|,\s*)O="?Python Software Foundation"?(,|$)') {
        throw "$Path is signed by '$subject', not the Python Software Foundation."
    }
}

function Assert-PinnedPython {
    # Returns the interpreter's base prefix once every check has passed.
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string]$Pinned
    )
    $parts = $Pinned.Split('.')
    Assert-PsfSigned -Path $Exe
    Assert-PsfSigned -Path (Join-Path -Path (Split-Path -Path $Exe -Parent) -ChildPath ('python{0}{1}.dll' -f $parts[0], $parts[1]))
    $probe = 'import platform, sys, sysconfig; ' +
        'print(platform.python_version()); print(sys.implementation.name); ' +
        'print(sys.maxsize > 2**32); print(bool(sysconfig.get_config_var(''Py_GIL_DISABLED''))); ' +
        'print(sys.prefix == sys.base_prefix); print(platform.machine()); print(sys.base_prefix)'
    $facts = @(Get-NativeOutput -What 'Asking the interpreter about itself' -FilePath $Exe -ArgumentList @('-I', '-c', $probe))
    if ($facts.Count -ne 7) {
        throw "Unexpected answer from $Exe."
    }
    if ($facts[0] -ne $Pinned) {
        throw "$Exe is Python $($facts[0]); .python-version pins $Pinned."
    }
    if ($facts[1] -ne 'cpython') {
        throw "$Exe is $($facts[1]), not CPython."
    }
    if ($facts[2] -ne 'True') {
        throw "$Exe is 32-bit; the build is x64 only."
    }
    if ($facts[3] -ne 'False') {
        throw "$Exe is the free-threaded build; use the standard python.exe."
    }
    if ($facts[4] -ne 'True') {
        throw "$Exe belongs to a virtual environment; pass the installed python.exe itself."
    }
    if ($facts[5] -ne 'AMD64') {
        throw "$Exe runs on $($facts[5]); the build is x64 (AMD64) only."
    }
    return [string]$facts[6]
}

function Get-NormalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\').ToLowerInvariant()
}

$previousProjectEnvironment = $env:UV_PROJECT_ENVIRONMENT
Push-Location -LiteralPath $RepoRoot
try {
    Write-Step 'Tools'
    foreach ($tool in @('git', 'uv')) {
        if ($null -eq (Get-Command -Name $tool -ErrorAction SilentlyContinue)) {
            throw "$tool is not on PATH."
        }
    }
    Invoke-Checked -What 'uv --version' -FilePath 'uv' -ArgumentList @('--version')

    Write-Step 'Clean checkout'
    $dirty = @(Get-NativeOutput -What 'git status' -FilePath 'git' -ArgumentList @('status', '--porcelain', '--untracked-files=all'))
    if ($dirty.Count -gt 0) {
        $dirty | ForEach-Object { Write-Host "  $_" }
        throw 'The checkout has uncommitted or untracked changes. Commit or remove them, then build again.'
    }
    $commit = [string](@(Get-NativeOutput -What 'git rev-parse' -FilePath 'git' -ArgumentList @('rev-parse', 'HEAD'))[0])
    Write-Host "Commit $commit"

    Write-Step 'Python'
    $pinned = (Get-Content -LiteralPath (Join-Path -Path $RepoRoot -ChildPath '.python-version') -TotalCount 1).Trim()
    if ($pinned -notmatch '^3\.14\.\d+$') {
        throw ".python-version must pin an exact 3.14 patch, not '$pinned'."
    }
    $tag = ($pinned.Split('.')[0..1]) -join '.'
    $exe = $Python
    if (-not $exe) {
        $exe = Find-RegisteredPython -Tag $tag
    }
    if (-not $exe) {
        $exe = Find-LauncherPython -Tag $tag
    }
    if (-not $exe) {
        throw "python.org CPython $tag was not found. Install Python $pinned (64-bit) from python.org, or pass -Python <path to python.exe>."
    }
    $exe = [System.IO.Path]::GetFullPath($exe)
    $basePrefix = Assert-PinnedPython -Exe $exe -Pinned $pinned
    Write-Host "Python $pinned from python.org, signed by the Python Software Foundation: $exe"

    Write-Step 'Fresh build folders'
    foreach ($name in @('build', 'dist')) {
        $path = Join-Path -Path $RepoRoot -ChildPath $name
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }

    Write-Step 'uv sync --locked --no-build'
    $venv = Join-Path -Path $RepoRoot -ChildPath 'build\venv'
    $env:UV_PROJECT_ENVIRONMENT = $venv
    Invoke-Checked -What 'uv sync' -FilePath 'uv' -ArgumentList @('sync', '--locked', '--no-build', '--no-python-downloads', '--python', $exe)
    $venvPython = Join-Path -Path $venv -ChildPath 'Scripts\python.exe'
    $venvBase = @(Get-NativeOutput -What 'Checking the build environment' -FilePath $venvPython -ArgumentList @('-I', '-c', 'import sys; print(sys.base_prefix)'))
    if ((Get-NormalPath -Path $venvBase[0]) -ne (Get-NormalPath -Path $basePrefix)) {
        throw "uv built the environment on $($venvBase[0]), not on the checked interpreter at $basePrefix."
    }

    Write-Step 'Version'
    $versionProbe = 'import tomllib; from network_analyser._version import __version__; ' +
        'print(__version__); print(tomllib.load(open(''pyproject.toml'', ''rb''))[''project''][''version''])'
    $versions = @(Get-NativeOutput -What 'Reading the version' -FilePath $venvPython -ArgumentList @('-E', '-c', $versionProbe))
    $version = [string]$versions[0]
    if ($version -notmatch '^0\.\d+\.\d+$') {
        throw "The version must be SemVer 0.y.z, not '$version'."
    }
    if ($versions[1] -ne $version) {
        throw "network_analyser/_version.py says $version but pyproject.toml says $($versions[1])."
    }
    Write-Host "Version $version"

    Write-Step 'Security tests'
    Invoke-Checked -What 'The security tests' -FilePath $venvPython -ArgumentList @('-E', '-m', 'pytest', '-m', 'security')

    Write-Step 'Licence check'
    $notices = Join-Path -Path $RepoRoot -ChildPath 'build\THIRD-PARTY-NOTICES.txt'
    Invoke-Checked -What 'The licence check' -FilePath $venvPython -ArgumentList @('-E', '-m', 'scripts.third_party_notices', '--out', $notices, '--product-version', $version)

    Write-Step 'PyInstaller (--onedir --noupx)'
    Invoke-Checked -What 'PyInstaller' -FilePath $venvPython -ArgumentList @('-E', '-m', 'PyInstaller', '--noconfirm', '--clean', '--distpath', 'dist', '--workpath', 'build\pyinstaller', 'scripts\network_analyser.spec')
    $buildDir = Join-Path -Path $RepoRoot -ChildPath 'dist\network-analyser'
    $builtExe = Join-Path -Path $buildDir -ChildPath 'network-analyser.exe'
    Copy-Item -LiteralPath $notices -Destination $buildDir

    Write-Step 'Version resource and first start'
    $resource = (Get-Item -LiteralPath $builtExe).VersionInfo
    if ($resource.ProductVersion -ne $version -or $resource.FileVersion -ne $version) {
        throw "The exe's version resource says $($resource.ProductVersion) / $($resource.FileVersion), not $version."
    }
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $printed = @(Get-NativeOutput -What 'network-analyser.exe --version' -FilePath $builtExe -ArgumentList @('--version'))
    $clock.Stop()
    if (($printed -join "`n").Trim() -ne "network-analyser $version") {
        throw "network-analyser.exe --version printed '$($printed -join ' ')', not 'network-analyser $version'."
    }
    $seconds = [math]::Round($clock.Elapsed.TotalSeconds, 1)
    Write-Host "Version resource $version matches --version; first start took $seconds s."
    if ($clock.Elapsed.TotalSeconds -gt $StartWarningSeconds) {
        Write-BuildWarning "The first start took $seconds s, over the $StartWarningSeconds s target (not a blocker; decision #32)."
    }

    Write-Step 'Zip and SHA256SUMS.txt'
    Invoke-Checked -What 'Packaging' -FilePath $venvPython -ArgumentList @('-E', '-m', 'scripts.package_build', '--build-dir', $buildDir, '--dist-dir', (Join-Path -Path $RepoRoot -ChildPath 'dist'), '--version', $version)
    $zip = Join-Path -Path $RepoRoot -ChildPath "dist\network-analyser-$version-win-x64.zip"
    if ((Get-Item -LiteralPath $zip).Length -gt $ZipSizeWarningBytes) {
        Write-BuildWarning 'The zip is over the 100 MB target (not a blocker; decision #32).'
    }

    Write-Step 'Checkout unchanged by the build'
    $after = @(Get-NativeOutput -What 'git status' -FilePath 'git' -ArgumentList @('status', '--porcelain', '--untracked-files=all'))
    $headAfter = [string](@(Get-NativeOutput -What 'git rev-parse' -FilePath 'git' -ArgumentList @('rev-parse', 'HEAD'))[0])
    if ($after.Count -gt 0 -or $headAfter -ne $commit) {
        throw 'The checkout changed while building, so the build may not match the commit. Build again.'
    }

    Write-Host ''
    Write-Host 'BUILD SUCCEEDED' -ForegroundColor Green
    Write-Host "  Commit:  $commit"
    Write-Host "  Version: $version"
    Write-Host "  Zip:     $zip"
    Write-Host "  Sums:    $(Join-Path -Path $RepoRoot -ChildPath 'dist\SHA256SUMS.txt')"
    Write-Host '  Signed:  no (v1 builds are unsigned, decision #32; SmartScreen will warn)'
    foreach ($warning in $Warnings) {
        Write-Host "  Warning: $warning" -ForegroundColor Yellow
    }
    Write-Host "To release exactly this build, ask a Claude session: release $commit as v$version"
    exit 0
}
catch {
    Write-Host ''
    Write-Host "BUILD FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    $env:UV_PROJECT_ENVIRONMENT = $previousProjectEnvironment
    Pop-Location
}
