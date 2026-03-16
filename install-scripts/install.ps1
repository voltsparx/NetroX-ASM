#Requires -Version 5.1

param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateSet("install","uninstall","update","test")]
    [string]$Action
)

$BINARY_NAME  = "NetroX-ASC"
$EXE_NAME     = "NetroX-ASC.exe"
$INSTALL_DIR  = "C:\Program Files\NetroX-ASC"
$INSTALL_BIN  = "$INSTALL_DIR\NetroX-ASC.exe"
$VERSION_FILE = "VERSION"
$BUILD_OUTPUT = "bin\NetroX-ASC.exe"
$TEST_DIR     = "test-tool"
$TEST_BIN     = "test-tool\NetroX-ASC.exe"

function Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "[-] $msg" -ForegroundColor Red }
function Info($msg) { Write-Host "    $msg" -ForegroundColor White }

function Read-Version {
    if (-not (Test-Path $VERSION_FILE)) {
        Fail "W002: VERSION file missing."
        exit 1
    }
    return (Get-Content $VERSION_FILE -ErrorAction Stop)
}

function Print-Banner {
    $ver = Read-Version
    Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   NetroX-ASC INSTALLER v$ver             " -ForegroundColor Cyan
    Write-Host "║   Pure x86_64 NASM network diagnostic    ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Check-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail "W001: Run PowerShell as Administrator"
        exit 2
    }
}

function Is-Installed {
    return (Test-Path $INSTALL_BIN)
}

function Get-InstalledVersion {
    $path = "$INSTALL_DIR\VERSION"
    if (Test-Path $path) { return (Get-Content $path) }
    return "unknown"
}

function Check-BuildTools {
    if (-not (Get-Command nasm -ErrorAction SilentlyContinue)) {
        Fail "W002: nasm not found. Download from https://www.nasm.us/"
        exit 1
    }
}

function Build-Binary {
    if (Get-Command make -ErrorAction SilentlyContinue) {
        Step "Building binary from source..."
        & make windows
        if ($LASTEXITCODE -ne 0) {
            Fail "W002: Build failed."
            exit 1
        }
        if (-not (Test-Path $BUILD_OUTPUT)) {
            Fail "W002: Binary missing after build."
            exit 1
        }
        Ok "Build successful: $BUILD_OUTPUT"
        return
    }
    if (-not (Test-Path $BUILD_OUTPUT)) {
        Fail "W002: Binary missing. Build first."
        exit 1
    }
}

function Add-ToPath {
    try {
        $pathKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        $current = (Get-ItemProperty -Path $pathKey -Name Path).Path
        if ($current -notlike "*$INSTALL_DIR*") {
            $newPath = "$current;$INSTALL_DIR"
            Set-ItemProperty -Path $pathKey -Name Path -Value $newPath
        }
        $signature = @"
[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, int Msg, IntPtr wParam, string lParam, int flags, int timeout, out IntPtr result);
"@
        Add-Type -MemberDefinition $signature -Name "Win32SendMessageTimeout" -Namespace Win32
        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x1A
        $result = [IntPtr]::Zero
        [Win32.Win32SendMessageTimeout]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [IntPtr]::Zero, "Environment", 2, 1000, [ref]$result) | Out-Null
    } catch {
        Warn "W010: PATH update failed. Add manually."
    }
}

function Remove-FromPath {
    try {
        $pathKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        $current = (Get-ItemProperty -Path $pathKey -Name Path).Path
        $parts = $current -split ';' | Where-Object { $_ -and ($_ -ne $INSTALL_DIR) }
        $newPath = ($parts -join ';')
        Set-ItemProperty -Path $pathKey -Name Path -Value $newPath
    } catch {
        Warn "W010: PATH update failed. Add manually."
    }
}

function Verify-Install {
    & $INSTALL_BIN --about | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail "W009: Install may be corrupt."
        exit 4
    }
}

function Do-Install {
    Check-Admin
    Print-Banner
    if (Is-Installed) {
        Warn "W006: Already installed. Use -update."
        exit 0
    }
    $ver = Read-Version
    if (Test-Path $BUILD_OUTPUT) {
        Step "Using pre-built binary"
    } else {
        Check-BuildTools
        Build-Binary
    }
    try {
        New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    } catch {
        Fail "W003: Access denied. Run as Admin."
        exit 1
    }
    try {
        Copy-Item $BUILD_OUTPUT $INSTALL_BIN -Force
    } catch {
        Fail "W003: Access denied. Run as Admin."
        exit 1
    }
    Copy-Item $VERSION_FILE "$INSTALL_DIR\VERSION" -Force
    Add-ToPath
    Verify-Install
    Write-Host "┌──────────────────────────────────────────┐"
    Write-Host "│  Installed NetroX-ASC v$ver             |"
    Write-Host "│  Binary: $INSTALL_BIN                    
    Write-Host "└──────────────────────────────────────────┘"
}

function Do-Uninstall {
    Check-Admin
    Print-Banner
    if (-not (Is-Installed)) {
        Warn "W007: Not installed. Nothing to remove."
        exit 0
    }
    $installedVer = Get-InstalledVersion
    try {
        Remove-Item $INSTALL_BIN -Force
    } catch {
        Warn "W003: Access denied. Run as Admin."
    }
    try {
        Remove-Item $INSTALL_DIR -Recurse -Force
    } catch {
        Warn "W003: Access denied. Run as Admin."
    }
    Remove-FromPath
    Write-Host "Uninstalled NetroX-ASC v$installedVer"
}

function Do-Update {
    Check-Admin
    Print-Banner
    if (-not (Is-Installed)) {
        Do-Install
        return
    }
    $newVer = Read-Version
    $installedVer = Get-InstalledVersion
    if ($newVer -eq $installedVer) {
        Ok "Already up to date."
        exit 0
    }
    if (-not (Test-Path $BUILD_OUTPUT)) {
        Check-BuildTools
        Build-Binary
    }
    try {
        Copy-Item $INSTALL_BIN "$INSTALL_BIN.bak" -Force
    } catch {
        Fail "W008: Cannot backup old binary. Abort."
        exit 1
    }
    try {
        Copy-Item $BUILD_OUTPUT $INSTALL_BIN -Force
    } catch {
        Copy-Item "$INSTALL_BIN.bak" $INSTALL_BIN -Force
        Fail "W002: Build failed."
        exit 1
    }
    Copy-Item $VERSION_FILE "$INSTALL_DIR\VERSION" -Force
    Verify-Install
    Remove-Item "$INSTALL_BIN.bak" -Force
    Write-Host "┌──────────────────────────────────────────┐"
    Write-Host "│  Updated NetroX-ASC $installedVer -> $newVer"
    Write-Host "└──────────────────────────────────────────┘"
}

function Run-Test($name, $args) {
    & $TEST_BIN $args | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Ok "Test passed: $name"
        return $true
    } else {
        Warn "Test failed: $name"
        return $false
    }
}

function Do-Test {
    Print-Banner
    if (-not (Test-Path $BUILD_OUTPUT)) {
        Check-BuildTools
        Build-Binary
    }
    New-Item -ItemType Directory -Path $TEST_DIR -Force | Out-Null
    Copy-Item $BUILD_OUTPUT $TEST_BIN -Force
    $passed = 0
    $failed = 0

    if (Run-Test "about" "--about") { $passed++ } else { $failed++ }
    if (Run-Test "help" "--help") { $passed++ } else { $failed++ }
    if (Run-Test "version-info" "--version-info") { $passed++ } else { $failed++ }
    if (Run-Test "scan" "127.0.0.1 --scan syn -p 80 --bench -T5") { $passed++ } else { $failed++ }

    Write-Host "$passed/4 tests passed"
    if ($failed -eq 0) {
        Write-Host "┌──────────────────────────┐"
        Write-Host "│  TEST SUITE PASSED       │"
        Write-Host "└──────────────────────────┘"
        exit 0
    } else {
        Write-Host "┌──────────────────────────┐"
        Write-Host "│  TEST SUITE FAILED       │"
        Write-Host "└──────────────────────────┘"
        exit 4
    }
}

switch ($Action) {
    "install"   { Do-Install }
    "uninstall" { Do-Uninstall }
    "update"    { Do-Update }
    "test"      { Do-Test }
}

