$ErrorActionPreference = "Stop"

# Set up environment variables
Set-Location (Split-Path $PSScriptRoot -Parent)
$root = Split-Path $PSScriptRoot -Parent
$buildDir = if ($env:NOVA_BUILD_DIR) { $env:NOVA_BUILD_DIR } else { "build" }
$buildRoot = Join-Path $root $buildDir
$env:SEL4_OUT_DIR = Join-Path $buildRoot "kernel"
$env:SEL4_KERNEL_DIR = Join-Path $root "kernel/seL4"

function Get-EnvInt {
    param(
        [string]$Name,
        [int]$Default,
        [int]$Min = [int]::MinValue,
        [int]$Max = [int]::MaxValue
    )

    $raw = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    $parsed = 0
    if ([int]::TryParse($raw, [ref]$parsed)) {
        if ($parsed -lt $Min) {
            return $Min
        }
        if ($parsed -gt $Max) {
            return $Max
        }
        return $parsed
    }

    return $Default
}

function Get-EnvDouble {
    param(
        [string]$Name,
        [double]$Default,
        [double]$Min,
        [double]$Max
    )

    $raw = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    $parsed = 0.0
    if ([double]::TryParse($raw, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
        if ($parsed -lt $Min) {
            return $Min
        }
        if ($parsed -gt $Max) {
            return $Max
        }
        return $parsed
    }

    return $Default
}

function Get-EnvBool {
    param(
        [string]$Name,
        [bool]$Default
    )

    $raw = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    switch ($raw.Trim().ToLowerInvariant()) {
        "1" { return $true }
        "true" { return $true }
        "yes" { return $true }
        "on" { return $true }
        "0" { return $false }
        "false" { return $false }
        "no" { return $false }
        "off" { return $false }
        default { return $Default }
    }
}

$script:testSleepScale = Get-EnvDouble "NOVA_TEST_SLEEP_SCALE" $(if ($IsLinux) { 0.25 } else { 1.0 }) 0.05 5.0
$script:testSleepFloorMs = Get-EnvInt "NOVA_TEST_MIN_SLEEP_MS" 0 0 1000
$script:testCharDelayMs = Get-EnvInt "NOVA_TEST_CHAR_DELAY_MS" $(if ($IsLinux) { 1 } else { 1 }) 0 1000
$script:testDefaultPostDelayMs = Get-EnvInt "NOVA_TEST_DEFAULT_POST_DELAY_MS" 150 0 10000
$script:testRmPostDelayMs = Get-EnvInt "NOVA_TEST_RM_POST_DELAY_MS" 450 0 10000
$script:testPollDelayMs = Get-EnvInt "NOVA_TEST_POLL_DELAY_MS" 5 0 1000
$script:testBulkSend = Get-EnvBool "NOVA_TEST_BULK_SEND" $false
$script:testStageTiming = Get-EnvBool "NOVA_TEST_STAGE_TIMING" $false
$script:testBigFileKb = Get-EnvInt "NOVA_TEST_BIGFILE_KB" $(if ($IsLinux) { 4 } else { 200 }) 1 4096
$bootTimeoutSeconds = Get-EnvInt "NOVA_TEST_BOOT_TIMEOUT_SECONDS" 120 30 600
$env:NOVA_LOG_LEVEL = Get-EnvInt "NOVA_LOG_LEVEL" 1 0 3

function Start-Sleep {
    [CmdletBinding(DefaultParameterSetName = "Milliseconds")]
    param(
        [Parameter(ParameterSetName = "Seconds")]
        [int]$Seconds,

        [Parameter(ParameterSetName = "Milliseconds")]
        [int]$Milliseconds
    )

    if ($PSCmdlet.ParameterSetName -eq "Seconds") {
        $Milliseconds = $Seconds * 1000
    }

    $effectiveMilliseconds = [int][Math]::Round($Milliseconds * $script:testSleepScale)
    if ($Milliseconds -gt 0 -and $effectiveMilliseconds -lt $script:testSleepFloorMs) {
        $effectiveMilliseconds = $script:testSleepFloorMs
    }

    if ($effectiveMilliseconds -gt 0) {
        Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds $effectiveMilliseconds
    }
}

function Write-StageProgress {
    param(
        [int]$Stage,
        [datetime]$StartTime
    )

    if (-not $script:testStageTiming) {
        return
    }

    $elapsedSeconds = [Math]::Round(((Get-Date) - $StartTime).TotalSeconds, 2)
    Write-Host ("`n[TEST][T+{0}s] Stage {1}" -f $elapsedSeconds, $Stage) -ForegroundColor DarkGray
}

function Invoke-TestIoSleepMs {
    param(
        [int]$Milliseconds
    )

    if ($Milliseconds -gt 0) {
        Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds $Milliseconds
    }
}

Write-Host "Building User App..." -ForegroundColor Cyan
Set-Location "services/user_app"
cargo build --target x86_64-unknown-none --release
if ($LASTEXITCODE -ne 0) { Write-Error "User App build failed"; exit 1 }
Set-Location "../.."

Write-Host "Building Serial Server..." -ForegroundColor Cyan
Set-Location "services/serial_server"
cargo build --target x86_64-unknown-none --release
if ($LASTEXITCODE -ne 0) { Write-Error "Serial Server build failed"; exit 1 }
Set-Location "../.."

Write-Host "Building FS Server..." -ForegroundColor Cyan
Set-Location "services/fs_server"
cargo build --target x86_64-unknown-none --release
if ($LASTEXITCODE -ne 0) { Write-Error "FS Server build failed"; exit 1 }
Set-Location "../.."

Write-Host "Building RootServer..." -ForegroundColor Cyan
Set-Location "services/rootserver"
cargo build --target x86_64-unknown-none --release
if ($LASTEXITCODE -ne 0) { Write-Error "RootServer build failed"; exit 1 }
Set-Location "../.."

$executable = Join-Path $root "target/x86_64-unknown-none/release/rootserver"
$kernelElf = Join-Path $buildRoot "kernel/kernel32.elf"
if (-not (Test-Path $kernelElf)) {
    Write-Error "Kernel (kernel32.elf) not found in $buildDir/kernel/. Please build the kernel first."
    exit 1
}

# QEMU Path
$qemu = "qemu-system-x86_64"
if (-not (Get-Command $qemu -ErrorAction SilentlyContinue)) {
    $commonPaths = @("C:\Program Files\qemu\qemu-system-x86_64.exe", "C:\Program Files (x86)\qemu\qemu-system-x86_64.exe")
    foreach ($path in $commonPaths) { if (Test-Path $path) { $qemu = $path; break } }
}

# Disk Image
$diskImg = Join-Path $root "disk.img"
# Default to a fresh disk for deterministic integration tests.
# Set NOVA_TEST_KEEP_DISK=1 to keep the previous image between runs.
if ((Test-Path $diskImg) -and ($env:NOVA_TEST_KEEP_DISK -ne "1")) {
    Write-Host "Resetting disk image for clean test run..." -ForegroundColor Gray
    Remove-Item -Force $diskImg
}
if (-not (Test-Path $diskImg)) {
    Write-Host "Creating 10MB disk image..." -ForegroundColor Gray
    $file = [System.IO.File]::Create($diskImg)
    try {
        $file.SetLength(10485760)
    } finally {
        $file.Dispose()
    }
}

# TCP Serial Port
$serialPort = 0
if ($env:NOVA_TEST_SERIAL_PORT) {
    $parsedSerialPort = 0
    if ([int]::TryParse($env:NOVA_TEST_SERIAL_PORT, [ref]$parsedSerialPort) -and $parsedSerialPort -gt 0) {
        $serialPort = $parsedSerialPort
    }
}
if ($serialPort -eq 0) {
    # Use a fixed range to avoid issues with immediate reuse of port 0
    $basePort = 56780
    for ($i = 0; $i -lt 100; $i++) {
        $tryPort = $basePort + $i
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $tryPort)
        try {
            $listener.Start()
            $serialPort = $tryPort
            break
        } catch {
            continue
        } finally {
            if ($null -ne $listener) { $listener.Stop() }
        }
    }
    # Add a small delay to ensure OS releases the port
    Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 100
}
if ($serialPort -eq 0) {
    Write-Error "Could not find a free port for QEMU serial"
    exit 1
}
$qemuAccelOverride = $env:NOVA_QEMU_ACCEL
$qemuCpuOverride = $env:NOVA_QEMU_CPU
$qemuMachineOverride = $env:NOVA_QEMU_MACHINE
$useKvm = $IsLinux -and (Test-Path "/dev/kvm")
$cpuModel = if ($qemuCpuOverride) {
    $qemuCpuOverride
} elseif ($useKvm) {
    "host"
} elseif ($IsLinux) {
    "max,+pcid,+pdpe1gb,+invpcid"
} else {
    "Haswell,+pdpe1gb"
}
$accel = if ($qemuAccelOverride) {
    $qemuAccelOverride
} elseif ($useKvm) {
    "kvm"
} else {
    "tcg,tb-size=64"
}
$qemuArgs = @(
    "-kernel", $kernelElf,
    "-initrd", $executable,
    "-serial", "tcp:127.0.0.1:$serialPort,server,wait",
    "-drive", "file=$diskImg,format=raw,index=0,media=disk",
    "-display", "none",
    "-m", "1024M"
)

if ($qemuMachineOverride) {
    $qemuArgs += @("-machine", $qemuMachineOverride)
}

$qemuArgs += @(
    "-cpu", $cpuModel,
    "-accel", $accel
)

Write-Host "Starting QEMU (Port $serialPort)..."
$process = Start-Process -FilePath $qemu -ArgumentList $qemuArgs -PassThru -NoNewWindow

# Wait for QEMU to start listening (with 'wait', it listens immediately)
# We use a loop to retry connection in case QEMU is slow to start
$client = New-Object System.Net.Sockets.TcpClient
$connected = $false
$retryCount = 0
$maxRetries = 20 # 2 seconds total with 100ms sleep

while (-not $connected -and $retryCount -lt $maxRetries) {
    if ($process.HasExited) {
        Write-Error "QEMU process exited immediately with code $($process.ExitCode). Check your arguments or kernel/initrd."
        exit 1
    }
    
    try {
        $client.Connect("127.0.0.1", $serialPort)
        $connected = $true
    } catch {
        $retryCount++
        Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 100
    }
}

if (-not $connected) {
    Write-Error "Failed to connect to QEMU serial port $serialPort after $maxRetries attempts."
    Stop-Process -InputObject $process -Force
    exit 1
}

Write-Host "Connected to QEMU Serial Port $serialPort" -ForegroundColor Green
$stream = $client.GetStream()
$stream.ReadTimeout = 100
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true
$reader = New-Object System.IO.StreamReader($stream)


$testPassed = $false
$stage = 0
$lastReportedStage = -1
$buffer = ""
$stage35Checks = @{
    serviceListSerial = $false
    serviceListFs = $false
    serviceResolve = $false
    fsPing = $false
    envExport = $false
    runHello = $false
    proxySmoke = $false
}
$timeoutSeconds = 120
$timeoutEnv = $env:NOVA_TEST_TIMEOUT_SECONDS
if ($timeoutEnv) {
    $parsedTimeout = 0
    if ([int]::TryParse($timeoutEnv, [ref]$parsedTimeout) -and $parsedTimeout -ge 30) {
        $timeoutSeconds = $parsedTimeout
    }
}

function Send-TestCommand {
    param(
        $Stream,
        [string]$Command,
        [int]$PostDelayMs = -1,
        [int]$CharDelayMs = -1
    )

    $bytes = [System.Text.Encoding]::ASCII.GetBytes("$Command`r")
    if ($CharDelayMs -lt 0) {
        $CharDelayMs = $script:testCharDelayMs
    }

    if ($script:testBulkSend -and $CharDelayMs -eq 0) {
        $Stream.Write($bytes, 0, $bytes.Length)
        $Stream.Flush()
    } else {
        foreach ($b in $bytes) {
            $Stream.WriteByte($b)
            $Stream.Flush()
            if ($CharDelayMs -gt 0) {
                Invoke-TestIoSleepMs $CharDelayMs
            }
        }
    }

    if ($PostDelayMs -lt 0) {
        if ($Command.StartsWith("rm ")) {
            $PostDelayMs = $script:testRmPostDelayMs
        } else {
            $PostDelayMs = $script:testDefaultPostDelayMs
        }
    }

    if ($PostDelayMs -gt 0) {
        Invoke-TestIoSleepMs $PostDelayMs
    }
}

$bootStartTime = Get-Date
$startTime = $bootStartTime
$pendingStageAction = $null

try {
    while (-not $process.HasExited) {
        $activeTimeoutSeconds = if ($stage -eq 0) { $bootTimeoutSeconds } else { $timeoutSeconds }
        $elapsedStartTime = if ($stage -eq 0) { $bootStartTime } else { $startTime }
        if ((Get-Date) - $elapsedStartTime -gt [TimeSpan]::FromSeconds($activeTimeoutSeconds)) {
            Write-Warning "Test Timed Out!"
            $elapsedSeconds = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
            Write-Host ("[TEST] Timed out at stage {0} after {1}s" -f $stage, $elapsedSeconds) -ForegroundColor Yellow
            if ($stage -eq 35) {
                Write-Host "Stage 35 partial matches:"
                $stage35Checks.GetEnumerator() | Sort-Object Name | ForEach-Object {
                    Write-Host ("  {0}={1}" -f $_.Name, $_.Value)
                }
            }
            Write-Host "Buffer Dump:"
            Write-Host $buffer
            break
        }

        if ($stream.DataAvailable) {
            $charBuffer = New-Object char[] 4096
            try {
                $count = $reader.Read($charBuffer, 0, $charBuffer.Length)
            } catch [System.IO.IOException] {
                continue
            }
                if ($count -gt 0) {
                    if ($stage -ne $lastReportedStage) {
                        Write-StageProgress -Stage $stage -StartTime $startTime
                        $lastReportedStage = $stage
                    }
                    $text = new-object String($charBuffer, 0, $count)
                    Write-Host -NoNewline $text
                    $buffer += $text
                
                # Keep a larger rolling window so verbose Linux debug traces do
                # not evict shell/test markers before the state machine sees them.
                if ($buffer.Length -gt 32768) {
                    $buffer = $buffer.Substring($buffer.Length - 32768)
                }
                
                # Stage 0: Wait for Shell Prompt
                if ($stage -eq 0 -and ($buffer -match "NovaOS:.*>" -or $buffer -match "NovaOS:/>")) {
                     Write-Host "`n[TEST] Shell Ready. Waiting for Process 0 to finish..." -ForegroundColor Yellow
                     $startTime = Get-Date
                     $stage = 1
                     $buffer = ""
                }
                
                if (
                    $stage -eq 1 -and
                    ($buffer -match "Process 0 exited") -and
                    (
                        $buffer -match "Service 'fs\.v1' marked ready" -or
                        $buffer -match "\[FS_SERVER\] service marked ready"
                    )
                ) {
                     Write-Host "`n[TEST] Process 0 Finished and fs_server Ready. Creating directory /home..." -ForegroundColor Yellow
                     $buffer = ""
                     Send-TestCommand $stream "mkdir /home" 120
                     $stage = 2
                     $pendingStageAction = $null
                }
                
                if ($stage -eq 2 -and $buffer -match "NovaOS:/.*>") {
                     if ($pendingStageAction -ne "cd_home") {
                         Write-Host ("`n[TEST] Entering /home...") -ForegroundColor Yellow
                         $pendingStageAction = "cd_home"
                     }
                }
                
                if ($stage -eq 3 -and (
                    $buffer -match "NovaOS:/home.*>" -or
                    $buffer -match "\[SHELL\] cd ok /home"
                )) {
                     if ($pendingStageAction -ne "write_bigfile") {
                         Write-Host ("`n[TEST] Writing large file ({0}KB)..." -f $script:testBigFileKb) -ForegroundColor Yellow
                         $pendingStageAction = "write_bigfile"
                     }
                }
                
                if ($stage -eq 4 -and $buffer -match "Write success") {
                     if ($pendingStageAction -ne "list_home") {
                         Write-Host "`n[TEST] Write Success. Listing directory..." -ForegroundColor Yellow
                         $pendingStageAction = "list_home"
                     }
                }

                if ($stage -eq 5 -and $buffer -match "big.bin") {
                     Write-Host "`n[TEST] File Verified. Leaving /home and checking non-empty directory protection..." -ForegroundColor Yellow
                     Send-TestCommand $stream "cd .." 80
                     $stage = 6
                     $buffer = ""
                }

                if ($stage -eq 6 -and (
                    $buffer -match "NovaOS:.*>" -or
                    $buffer -match "\[SHELL\] cd ok /"
                )) {
                     Write-Host "`n[TEST] Attempting to remove non-empty directory (should fail)..." -ForegroundColor Yellow
                     Send-TestCommand $stream "rm /home"
                     $stage = 7
                     $buffer = ""
                }
                
                if ($stage -eq 7 -and $buffer -match "Directory not empty") {
                     Write-Host "`n[TEST] Protection Verified. Removing file..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "rm /home/big.bin"
                     $stage = 8
                     $buffer = ""
                }
                
                if ($stage -eq 8 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Removing directory..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "rm /home"
                     $stage = 9
                     $buffer = ""
                }
                
                if ($stage -eq 9 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Testing Metadata (ls output)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "touch meta.txt" 500
                     Send-TestCommand $stream "ls meta.txt"
                     
                     $stage = 10
                     $buffer = ""
                }

                if ($stage -eq 10 -and $buffer -match "202.-..-.. ..:..:..") {
                     Write-Host "`n[TEST] Metadata Verified. Testing Encryption..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "touch secret.txt" 1200
                     Send-TestCommand $stream "encrypt secret.txt" 1200
                     Send-TestCommand $stream "echo SecretData > secret.txt"
                     
                     $stage = 11
                     $buffer = ""
                }
                
                if ($stage -eq 11 -and $buffer -match "Written to .*secret.txt") {
                     Write-Host "`n[TEST] Encrypted Write Success. Verifying Transparent Read..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "cat secret.txt"
                     
                     $stage = 12
                     $buffer = ""
                }

                if ($stage -eq 12 -and $buffer -match "SecretData") {
                     Write-Host "`n[TEST] Transparent Read Success. Decrypting (Removing Flag) to check Ciphertext..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "decrypt secret.txt" 1200
                     Send-TestCommand $stream "cat secret.txt"
                     
                     $stage = 13
                     $buffer = ""
                }

                if ($stage -eq 13 -and $buffer -match "NovaOS:.*>" -and -not ($buffer -match "SecretData")) {
                     Write-Host "`n[TEST] Encryption Verified. Testing Hard Links..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "touch link_src.txt" 1200
                     Send-TestCommand $stream "ln link_src.txt link_dest.txt"
                     
                     $stage = 14
                     $buffer = ""
                }

                if ($stage -eq 14 -and $buffer -match "Created hard link") {
                     Write-Host "`n[TEST] Hard Link Created. Verifying Link Count..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "ls link_src.txt"
                     
                     $stage = 15
                     $buffer = ""
                }

                if (
                    $stage -eq 15 -and (
                        ($buffer -match "\[FS_CMD\] ls ok .*link_src\.txt" -and $buffer -match "link_src\.txt" -and $buffer -match "(?:^|[^0-9])2(?:[^0-9]|$)") -or
                        ($buffer -match "rw-r--r--" -and $buffer -match "link_src\.txt" -and $buffer -match "(?:^|[^0-9])2(?:[^0-9]|$)")
                    )
                ) {
                     Write-Host "`n[TEST] Link Count Verified (2). Testing Content Synchronization..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "echo LinkData > link_src.txt" 1200
                     Send-TestCommand $stream "cat link_dest.txt"

                     $stage = 16
                     $buffer = ""
                }

                if ($stage -eq 16 -and $buffer -match "LinkData") {
                     Write-Host "`n[TEST] Content Sync Verified. Testing Unlink (Source Removal)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "rm link_src.txt"
                     Send-TestCommand $stream "cat link_dest.txt"
                     
                     $stage = 17
                     $buffer = ""
                }

                if ($stage -eq 17 -and $buffer -match "LinkData") {
                     Write-Host "`n[TEST] Unlink Verified (Data Persists). Cleaning up..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "rm link_dest.txt"
                     
                     $stage = 18
                     $buffer = ""
                }

                if ($stage -eq 18 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Hard Link Verified. Testing Metadata..." -ForegroundColor Yellow
                     $pendingStageAction = "meta_touch"
                }

                if ($stage -eq 18.1 -and $buffer -match "\[FS_CMD\] touch ok .*meta_test\.txt") {
                     Write-Host "`n[TEST] Metadata Touch Verified. Setting mode..." -ForegroundColor Yellow
                     Send-TestCommand $stream "chmod 777 meta_test.txt" 120
                     $stage = 18.2
                     $buffer = ""
                }

                if ($stage -eq 18.2 -and $buffer -match "\[FS_CMD\] chmod ok .*meta_test\.txt") {
                     Write-Host "`n[TEST] Metadata Mode Verified. Setting owner..." -ForegroundColor Yellow
                     Send-TestCommand $stream "chown 1000:1000 meta_test.txt" 120
                     $stage = 18.3
                     $buffer = ""
                }

                if ($stage -eq 18.3 -and $buffer -match "\[FS_CMD\] chown ok .*meta_test\.txt") {
                     Write-Host "`n[TEST] Metadata Owner Verified. Verifying ls output..." -ForegroundColor Yellow
                     Send-TestCommand $stream "ls meta_test.txt" 120
                     $stage = 19
                     $buffer = ""
                }

                if ($stage -eq 19 -and ($buffer -match "rwxrwxrwx.*1000.*1000" -or $buffer -match "meta_test\.txt.*1000.*1000" -or $buffer -match "1000.*1000.*meta_test\.txt")) {
                     Write-Host "`n[TEST] Metadata Verified. Cleaning up..." -ForegroundColor Yellow
                     $buffer = ""
                     Send-TestCommand $stream "rm meta_test.txt" 120
                     $stage = 20
                     $pendingStageAction = $null
                }

                if ($stage -eq 20 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Metadata Verified. Testing Symbolic Links..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "touch sym_src.txt" 200
                     Send-TestCommand $stream "echo SymData > sym_src.txt" 200
                     Send-TestCommand $stream "ln -s sym_src.txt sym_link"
                     
                     $stage = 21
                     $buffer = ""
                }

                if ($stage -eq 21 -and $buffer -match "Created symbolic link") {
                     Write-Host "`n[TEST] Symlink Created. Verifying via ls..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "ls sym_link"
                     
                     $stage = 22
                     $buffer = ""
                }

                if ($stage -eq 22 -and $buffer -match "sym_link -> sym_src.txt") {
                     Write-Host "`n[TEST] Symlink Display Verified. Reading through symlink..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "cat sym_link"
                     
                     $stage = 23
                     $buffer = ""
                }

                if ($stage -eq 23 -and $buffer -match "SymData") {
                     Write-Host "`n[TEST] Symlink Read Verified. Testing Symlink Removal..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "rm sym_link"
                     
                     $stage = 24
                     $buffer = ""
                }

                if ($stage -eq 24 -and $buffer -match "Removed" -and $buffer -match "sym_link") {
                     Write-Host "`n[TEST] Symlink Removed. Verifying Target Persists..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "cat sym_src.txt"
                     
                     $stage = 25
                     $buffer = ""
                }

                if ($stage -eq 25 -and $buffer -match "SymData") {
                     Write-Host "`n[TEST] Target Persistence Verified. Cleaning up..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "rm sym_src.txt"
                     
                     $stage = 26
                     $buffer = ""
                }

                if ($stage -eq 26 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Symlink Listing Verified. Moving to Rename Tests..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     
                     # --- Rename Test (File) ---
                     # Clean up potential leftovers from previous runs
                     Send-TestCommand $stream "rm old_name"
                     Send-TestCommand $stream "rm new_name"
                     
                     # 1. Create a file to rename
                     Send-TestCommand $stream "echo rename_me content > old_name"
                     $stage = 27
                     $buffer = ""
                }

                if ($stage -eq 27 -and $buffer -match "Written to") {
                     Write-Host "`n[TEST] File created. Renaming 'old_name' to 'new_name'..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "mv old_name new_name"
                     $stage = 28
                     $buffer = ""
                }

                if (
                    $stage -eq 28 -and (
                        $buffer -match "Renamed '.*old_name' to '.*new_name'" -or
                        ($buffer -match "\[FS_CMD\] mv ok" -and $buffer -match "old_name" -and $buffer -match "new_name")
                    )
                ) {
                     Write-Host "`n[TEST] Rename command successful. Verifying file existence..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     # Verify old name is gone
                     Send-TestCommand $stream "cat old_name"
                     $stage = 29
                     $buffer = ""
                }

                if (
                    $stage -eq 29 -and (
                        $buffer -match "File not found" -or
                        ($buffer -match "open failed" -and $buffer -match "old_name")
                    )
                ) {
                     Write-Host "`n[TEST] Old name gone. Checking new name..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "cat new_name"
                     $stage = 30
                     $buffer = ""
                }

                if ($stage -eq 30 -and $buffer -match "rename_me content") {
                     Write-Host "`n[TEST] New name content verified. Testing Symlink Rename..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     
                     # --- Rename Test (Symlink) ---
                     # Clean up potential leftovers
                     Send-TestCommand $stream "rm link_old"
                     Send-TestCommand $stream "rm link_new"

                     # 1. Create a symlink
                     Send-TestCommand $stream "ln -s new_name link_old"
                     $stage = 31
                     $buffer = ""
                }

                if ($stage -eq 31 -and $buffer -match "Created symbolic link") {
                     Write-Host "`n[TEST] Symlink created. Renaming 'link_old' to 'link_new'..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "mv link_old link_new"
                     $stage = 32
                     $buffer = ""
                }

                if (
                    $stage -eq 32 -and (
                        $buffer -match "Renamed '.*link_old' to '.*link_new'" -or
                        ($buffer -match "\[FS_CMD\] mv ok" -and $buffer -match "link_old" -and $buffer -match "link_new")
                    )
                ) {
                     Write-Host "`n[TEST] Symlink rename successful. Verifying link target..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "ls link_new"
                     $stage = 33
                     $buffer = ""
                }

                if ($stage -eq 33 -and $buffer -match "-> new_name") {
                     Write-Host "`n[TEST] Symlink Rename Verified! Testing Process Management..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "ps"
                     $stage = 34
                     $buffer = ""
                }
                
                if ($stage -eq 34 -and $buffer -match "PID.*PPID.*State.*Name") {
                     Write-Host "`n[TEST] PS Headers Verified. Testing Service Registry + Env + runhello..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $stage35Checks = @{
                        serviceListSerial = $false
                        serviceListFs = $false
                        serviceResolve = $false
                        fsPing = $false
                        envExport = $false
                        cpSeedWrite = $false
                        cpCommand = $false
                        cpReadback = $false
                        runHello = $false
                        proxySmoke = $false
                     }

                     # 1. Verify service registry visibility
                     Send-TestCommand $stream "services" 200

                     # 2. Verify version-aware service resolve
                     Send-TestCommand $stream "svc serial" 200

                     # 3. Verify fs service health ping
                     Send-TestCommand $stream "fsping" 200

                     # 4. Export Environment Variable
                     Send-TestCommand $stream "export TEST_ENV=NovaTest" 200

                     # 5. Verify shell env store
                     Send-TestCommand $stream "env" 200

                     # 6. Seed and verify a minimal cp path that will hit the fs helper
                     Send-TestCommand $stream "rm cp_src.txt"
                     Send-TestCommand $stream "rm cp_dest.txt"
                     Send-TestCommand $stream "echo CopyData > cp_src.txt" 200
                     Send-TestCommand $stream "cp cp_src.txt cp_dest.txt" 1200
                     Send-TestCommand $stream "cat cp_dest.txt" 1200

                     # 7. Run 'runhello' with an fs_server persistent-proxy smoke mode
                     Send-TestCommand $stream "runhello fs_proxy_smoke" 200

                     $stage = 35
                     $buffer = ""
                }

                if ($stage -eq 35) {
                    if ($buffer -match "serial\.v1") {
                        $stage35Checks.serviceListSerial = $true
                    }
                    if ($buffer -match "fs\.v1") {
                        $stage35Checks.serviceListFs = $true
                    }
                    if ($buffer -match "service serial => serial\.v1") {
                        $stage35Checks.serviceResolve = $true
                    }
                    if ($buffer -match "\[SVC\] fs ping ok \(proto v1\)") {
                        $stage35Checks.fsPing = $true
                    }
                    if ($buffer -match "TEST_ENV=NovaTest") {
                        $stage35Checks.envExport = $true
                    }
                    if (
                        ($buffer -match "Written to" -and $buffer -match "cp_src\.txt") -or
                        ($buffer -match "\[FS_CMD\] write ok" -and $buffer -match "cp_src\.txt")
                    ) {
                        $stage35Checks.cpSeedWrite = $true
                    }
                    if ($buffer -match "\[FS_CMD\] cp ok" -or $buffer -match "Copied '.*cp_src\.txt' to '.*cp_dest\.txt'") {
                        $stage35Checks.cpCommand = $true
                    }
                    if ($buffer -match "CopyData") {
                        $stage35Checks.cpReadback = $true
                    }
                    if ($buffer -match "\[RUN\] Process spawned successfully") {
                        $stage35Checks.runHello = $true
                    }
                    if ($buffer -match "\[FS_PROXY\] PASS") {
                        $stage35Checks.proxySmoke = $true
                    }
                }

                if (
                    $stage -eq 35 -and
                    $stage35Checks.serviceListSerial -and
                    $stage35Checks.serviceListFs -and
                    $stage35Checks.serviceResolve -and
                    $stage35Checks.fsPing -and
                    $stage35Checks.envExport -and
                    $stage35Checks.cpSeedWrite -and
                    $stage35Checks.cpCommand -and
                    $stage35Checks.cpReadback -and
                    $stage35Checks.runHello -and
                    $stage35Checks.proxySmoke
                ) {
                     Write-Host "`n[TEST] Service Registry + Env + runhello Verified. Testing Directory Rename..." -ForegroundColor Yellow
                     
                     $stage = 36
                     $buffer = ""
                     
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "rm cp_src.txt"
                     Send-TestCommand $stream "rm cp_dest.txt"
                     Send-TestCommand $stream "mkdir dir_old"
                }

                if ($stage -eq 36 -and $buffer -match "NovaOS:.*>") { 
                     # Wait for prompt after mkdir before proceeding to rename
                     Send-TestCommand $stream "touch dir_old/file.txt" 200
                     Send-TestCommand $stream "mv dir_old dir_new"
                     
                     $stage = 37
                     $buffer = ""
                }

                if ($stage -eq 37 -and $buffer -match "Renamed") {
                     Write-Host "`n[TEST] Directory Rename Executed. Verifying Content..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "ls dir_new"
                     
                     $stage = 38
                     $buffer = ""
                }

                if ($stage -eq 38 -and $buffer -match "file.txt") {
                     Write-Host "`n[TEST] Directory Content Verified! Testing Encryption..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "touch secret.txt" 200
                     Send-TestCommand $stream "encrypt secret.txt" 200
                     Send-TestCommand $stream "writetest secret.txt 1"
                     
                     $stage = 39
                     $buffer = ""
                }

                if ($stage -eq 39 -and $buffer -match "Write success") {
                     Write-Host "`n[TEST] Encrypted Write Success. Reading encrypted file (should be cleartext)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "cat secret.txt"
                     
                     $stage = 40
                     $buffer = ""
                }

                if ($stage -eq 40 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Transparent Read Done. Decrypting..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "decrypt secret.txt" 200
                     Send-TestCommand $stream "cat secret.txt"
                     
                     $stage = 41
                     $buffer = ""
                }

                if ($stage -eq 41 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Raw Read Done (Ciphertext check). Testing Truncate (Extend)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "touch trunc.txt" 200
                     Send-TestCommand $stream "echo data > trunc.txt" 200
                     Send-TestCommand $stream "truncate trunc.txt 100"
                     
                     $stage = 42
                     $buffer = ""
                }

                if ($stage -eq 42 -and (
                    $buffer -match "Truncated '.*trunc.txt' to 100 bytes" -or
                    $buffer -match "\[FS_CMD\] truncate ok"
                )) {
                     Write-Host "`n[TEST] Extend Verified. Checking LS size..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "ls trunc.txt"
                     
                     $stage = 43
                     $buffer = ""
                }

                if (
                    $stage -eq 43 -and (
                        ($buffer -match "\[FS_CMD\] ls ok .*trunc\.txt" -and $buffer -match "trunc\.txt" -and $buffer -match "(?:^|[^0-9])100(?:[^0-9]|$)") -or
                        ($buffer -match "rw-r--r--" -and $buffer -match "trunc\.txt" -and $buffer -match "(?:^|[^0-9])100(?:[^0-9]|$)")
                    )
                ) {
                     Write-Host "`n[TEST] Size 100 Verified. Testing Truncate (Shrink)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "truncate trunc.txt 5"
                     
                     $stage = 44
                     $buffer = ""
                }

                if ($stage -eq 44 -and (
                    $buffer -match "Truncated '.*trunc.txt' to 5 bytes" -or
                    $buffer -match "\[FS_CMD\] truncate ok"
                )) {
                     Write-Host "`n[TEST] Shrink Verified. Checking Content..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "cat trunc.txt"
                     
                     $stage = 45
                     $buffer = ""
                }

                if ($stage -eq 45 -and $buffer -match "data") {
                     Write-Host "`n[TEST] Content Verified. Testing Sparse File (Large Truncate)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "truncate sparse.bin 10240"
                     
                     $stage = 46
                     $buffer = ""
                }

                if ($stage -eq 46 -and (
                    $buffer -match "Truncated '.*sparse\.bin' to 10240 bytes" -or
                    $buffer -match "\[FS_CMD\] truncate ok"
                )) {
                     Write-Host "`n[TEST] Sparse Create Verified. Checking LS size..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "ls sparse.bin"
                     
                     $stage = 47
                     $buffer = ""
                }

                if (
                    $stage -eq 47 -and (
                        ($buffer -match "\[FS_CMD\] ls ok .*sparse\.bin" -and $buffer -match "sparse\.bin" -and $buffer -match "(?:^|[^0-9])10240(?:[^0-9]|$)") -or
                        ($buffer -match "rw-r--r--" -and $buffer -match "sparse\.bin" -and $buffer -match "(?:^|[^0-9])10240(?:[^0-9]|$)")
                    )
                ) {
                     Write-Host "`n[TEST] Sparse Size Verified. Testing Sync..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "sync"
                     
                     $stage = 48
                     $buffer = ""
                }

                if ($stage -eq 48 -and $buffer -match "FileSystem synced") {
                     Write-Host "`n[TEST] Sync Verified. Cleaning up..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "rm trunc.txt"
                     Send-TestCommand $stream "rm sparse.bin"
                     
                     $stage = 49
                     $buffer = ""
                }

                if ($stage -eq 49 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Cleanup Done." -ForegroundColor Green
                     Write-Host "All Tests Passed" -ForegroundColor Green
                     $testPassed = $true
                     break
                }
            }
        }

        if ($pendingStageAction -and ($buffer -match "NovaOS:.*>" -or $buffer -match "NovaOS:/>")) {
            switch ($pendingStageAction) {
                "cd_home" {
                    $buffer = ""
                    Send-TestCommand $stream "cd /home" 80
                    $stage = 3
                    $pendingStageAction = $null
                }
                "write_bigfile" {
                    $buffer = ""
                    Send-TestCommand $stream "writetest big.bin $($script:testBigFileKb)" 120
                    $stage = 4
                    $pendingStageAction = $null
                }
                "list_home" {
                    $buffer = ""
                    Send-TestCommand $stream "ls" 120
                    $stage = 5
                    $pendingStageAction = $null
                }
                "meta_touch" {
                    $buffer = ""
                    Send-TestCommand $stream "touch meta_test.txt" 120
                    $stage = 18.1
                    $pendingStageAction = $null
                }
                "meta_chmod" {
                    $buffer = ""
                    Send-TestCommand $stream "chmod 777 meta_test.txt" 120
                    $stage = 18.2
                    $pendingStageAction = $null
                }
                "meta_chown" {
                    $buffer = ""
                    Send-TestCommand $stream "chown 1000:1000 meta_test.txt" 120
                    $stage = 18.3
                    $pendingStageAction = $null
                }
                "meta_ls" {
                    $buffer = ""
                    Send-TestCommand $stream "ls meta_test.txt" 120
                    $stage = 19
                    $pendingStageAction = $null
                }
            }
        }

        if (-not $stream.DataAvailable) {
            Start-Sleep -Milliseconds $script:testPollDelayMs
        }
    }
} finally {
    $client.Close()
    if (-not $process.HasExited) {
        Stop-Process -InputObject $process -Force
    }
}

if ($testPassed) {
    exit 0
} else {
    Write-Error "Test Failed or Timed Out"
    exit 1
}
