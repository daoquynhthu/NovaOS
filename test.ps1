$ErrorActionPreference = "Stop"

# Set up environment variables
Set-Location $PSScriptRoot
$root = $PSScriptRoot
$buildDir = if ($env:NOVA_BUILD_DIR) { $env:NOVA_BUILD_DIR } else { "build" }
$buildRoot = Join-Path $root $buildDir
$env:SEL4_OUT_DIR = Join-Path $buildRoot "kernel"
$env:SEL4_KERNEL_DIR = Join-Path $root "kernel/seL4"

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
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        $serialPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
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

Write-Host "Starting QEMU..."
$process = Start-Process -FilePath $qemu -ArgumentList $qemuArgs -PassThru -NoNewWindow

# Wait for QEMU to start listening (with 'wait', it listens immediately)
Start-Sleep -Milliseconds 500

$client = New-Object System.Net.Sockets.TcpClient
try {
    $client.Connect("127.0.0.1", $serialPort)
    Write-Host "Connected to QEMU Serial Port $serialPort" -ForegroundColor Green
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($stream)
} catch {
    Write-Error "Failed to connect to QEMU serial port: $_"
    Stop-Process -InputObject $process -Force
    exit 1
}

$testPassed = $false
$stage = 0
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
        [int]$CharDelayMs = 10
    )

    $bytes = [System.Text.Encoding]::ASCII.GetBytes("$Command`r`n")
    foreach ($b in $bytes) {
        $Stream.WriteByte($b)
        $Stream.Flush()
        Start-Sleep -Milliseconds $CharDelayMs
    }

    if ($PostDelayMs -lt 0) {
        if ($Command.StartsWith("rm ")) {
            $PostDelayMs = 1200
        } else {
            $PostDelayMs = 200
        }
    }

    if ($PostDelayMs -gt 0) {
        Start-Sleep -Milliseconds $PostDelayMs
    }
}

$startTime = Get-Date

try {
    while (-not $process.HasExited) {
        if ((Get-Date) - $startTime -gt [TimeSpan]::FromSeconds($timeoutSeconds)) {
            Write-Warning "Test Timed Out!"
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
            $count = $reader.Read($charBuffer, 0, $charBuffer.Length)
            if ($count -gt 0) {
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
                     $stage = 1
                     $buffer = ""
                }
                
                if ($stage -eq 1 -and ($buffer -match "Process 0 exited")) {
                     Write-Host "`n[TEST] Process 0 Finished. Creating directory /home..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 1000
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("mkdir /home`r`n")
                     Write-Host "`n[DEBUG] Sending bytes: $($bytes -join ' ')"
                     foreach ($b in $bytes) {
                        $stream.WriteByte($b)
                        $stream.Flush()
                        Start-Sleep -Milliseconds 2
                     }
                     $stage = 2
                     $buffer = ""
                }
                
                if ($stage -eq 2 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Changing directory to /home..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 1200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cd /home`r`n")
                     foreach ($b in $bytes) {
                        $stream.WriteByte($b)
                        $stream.Flush()
                        Start-Sleep -Milliseconds 2
                     }
                     $stage = 3
                     $buffer = ""
                }
                
                if ($stage -eq 3 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Writing large file (200KB)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("writetest big.bin 200`r`n")
                     foreach ($b in $bytes) {
                        $stream.WriteByte($b)
                        $stream.Flush()
                        Start-Sleep -Milliseconds 2
                     }
                     $stage = 4
                     $buffer = ""
                }
                
                if ($stage -eq 4 -and $buffer -match "Write success") {
                     Write-Host "`n[TEST] Write Success. Listing directory..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ls`r`n")
                     foreach ($b in $bytes) {
                        $stream.WriteByte($b)
                        $stream.Flush()
                        Start-Sleep -Milliseconds 2
                     }
                     $stage = 5
                     $buffer = ""
                }

                if ($stage -eq 5 -and $buffer -match "big.bin") {
                     Write-Host "`n[TEST] File Verified. Moving up..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cd ..`r`n")
                     foreach ($b in $bytes) {
                        $stream.WriteByte($b)
                        $stream.Flush()
                        Start-Sleep -Milliseconds 10
                     }
                     $stage = 6
                     $buffer = ""
                }

                if ($stage -eq 6 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Attempting to remove non-empty directory (should fail)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
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
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("touch meta.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ls meta.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 10
                     $buffer = ""
                }

                if ($stage -eq 10 -and $buffer -match "202.-..-.. ..:..:..") {
                     Write-Host "`n[TEST] Metadata Verified. Testing Encryption..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("touch secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 1200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("encrypt secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 1200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("echo SecretData > secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 11
                     $buffer = ""
                }
                
                if ($stage -eq 11 -and $buffer -match "Written to .*secret.txt") {
                     Write-Host "`n[TEST] Encrypted Write Success. Verifying Transparent Read..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 12
                     $buffer = ""
                }

                if ($stage -eq 12 -and $buffer -match "SecretData") {
                     Write-Host "`n[TEST] Transparent Read Success. Decrypting (Removing Flag) to check Ciphertext..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("decrypt secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 1200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 13
                     $buffer = ""
                }

                if ($stage -eq 13 -and $buffer -match "NovaOS:.*>" -and -not ($buffer -match "SecretData")) {
                     Write-Host "`n[TEST] Encryption Verified. Testing Hard Links..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("touch link_src.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 1200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ln link_src.txt link_dest.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 14
                     $buffer = ""
                }

                if ($stage -eq 14 -and $buffer -match "Created hard link") {
                     Write-Host "`n[TEST] Hard Link Created. Verifying Link Count..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ls link_src.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 15
                     $buffer = ""
                }

                if ($stage -eq 15 -and $buffer -match "rw-.* 2 .*link_src.txt") {
                     Write-Host "`n[TEST] Link Count Verified (2). Testing Content Synchronization..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("echo LinkData > link_src.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 1200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat link_dest.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }

                     $stage = 16
                     $buffer = ""
                }

                if ($stage -eq 16 -and $buffer -match "LinkData") {
                     Write-Host "`n[TEST] Content Sync Verified. Testing Unlink (Source Removal)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "rm link_src.txt"
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat link_dest.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
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
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("touch meta_test.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 1200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("chmod 777 meta_test.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("chown 1000:1000 meta_test.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ls meta_test.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 19
                     $buffer = ""
                }

                if ($stage -eq 19 -and $buffer -match "rwxrwxrwx.*1000.*1000") {
                     Write-Host "`n[TEST] Metadata Verified. Cleaning up..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     Send-TestCommand $stream "rm meta_test.txt"
                     
                     $stage = 20
                     $buffer = ""
                }

                if ($stage -eq 20 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Metadata Verified. Testing Symbolic Links..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("touch sym_src.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("echo SymData > sym_src.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ln -s sym_src.txt sym_link`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 21
                     $buffer = ""
                }

                if ($stage -eq 21 -and $buffer -match "Created symbolic link") {
                     Write-Host "`n[TEST] Symlink Created. Verifying via ls..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ls sym_link`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 22
                     $buffer = ""
                }

                if ($stage -eq 22 -and $buffer -match "sym_link -> sym_src.txt") {
                     Write-Host "`n[TEST] Symlink Display Verified. Reading through symlink..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat sym_link`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
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
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat sym_src.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
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
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("echo rename_me content > old_name`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     $stage = 27
                     $buffer = ""
                }

                if ($stage -eq 27 -and $buffer -match "Written to") {
                     Write-Host "`n[TEST] File created. Renaming 'old_name' to 'new_name'..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("mv old_name new_name`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
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
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat old_name`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     $stage = 29
                     $buffer = ""
                }

                if ($stage -eq 29 -and $buffer -match "File not found") {
                     Write-Host "`n[TEST] Old name gone. Checking new name..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat new_name`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
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
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ln -s new_name link_old`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     $stage = 31
                     $buffer = ""
                }

                if ($stage -eq 31 -and $buffer -match "Created symbolic link") {
                     Write-Host "`n[TEST] Symlink created. Renaming 'link_old' to 'link_new'..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("mv link_old link_new`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
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
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ls link_new`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     $stage = 33
                     $buffer = ""
                }

                if ($stage -eq 33 -and $buffer -match "-> new_name") {
                     Write-Host "`n[TEST] Symlink Rename Verified! Testing Process Management..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ps`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
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
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("services`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200

                     # 2. Verify version-aware service resolve
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("svc serial`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200

                     # 3. Verify fs service health ping
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("fsping`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200

                     # 4. Export Environment Variable
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("export TEST_ENV=NovaTest`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200

                     # 5. Verify shell env store
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("env`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200

                     # 6. Seed and verify a minimal cp path that will hit the fs helper
                     Send-TestCommand $stream "rm cp_src.txt"
                     Send-TestCommand $stream "rm cp_dest.txt"
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("echo CopyData > cp_src.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cp cp_src.txt cp_dest.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 1200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat cp_dest.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 1200

                     # 7. Run 'runhello' with an fs_server persistent-proxy smoke mode
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("runhello fs_proxy_smoke`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200

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
                    if ($buffer -match "Written to /cp_src\.txt") {
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
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("mkdir dir_old`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                }

                if ($stage -eq 36 -and $buffer -match "NovaOS:.*>") { 
                     # Wait for prompt after mkdir before proceeding to rename
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("touch dir_old/file.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("mv dir_old dir_new`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 37
                     $buffer = ""
                }

                if ($stage -eq 37 -and $buffer -match "Renamed") {
                     Write-Host "`n[TEST] Directory Rename Executed. Verifying Content..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ls dir_new`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 38
                     $buffer = ""
                }

                if ($stage -eq 38 -and $buffer -match "file.txt") {
                     Write-Host "`n[TEST] Directory Content Verified! Testing Encryption..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("touch secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("encrypt secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("writetest secret.txt 1`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 39
                     $buffer = ""
                }

                if ($stage -eq 39 -and $buffer -match "Write success") {
                     Write-Host "`n[TEST] Encrypted Write Success. Reading encrypted file (should be cleartext)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 40
                     $buffer = ""
                }

                if ($stage -eq 40 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Transparent Read Done. Decrypting..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("decrypt secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat secret.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 41
                     $buffer = ""
                }

                if ($stage -eq 41 -and $buffer -match "NovaOS:.*>") {
                     Write-Host "`n[TEST] Raw Read Done (Ciphertext check). Testing Truncate (Extend)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("touch trunc.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("echo data > trunc.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     Start-Sleep -Milliseconds 200
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("truncate trunc.txt 100`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 42
                     $buffer = ""
                }

                if ($stage -eq 42 -and $buffer -match "Truncated '.*trunc.txt' to 100 bytes") {
                     Write-Host "`n[TEST] Extend Verified. Checking LS size..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ls trunc.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 43
                     $buffer = ""
                }

                if ($stage -eq 43 -and $buffer -match "rw-.* 100 .*trunc.txt") {
                     Write-Host "`n[TEST] Size 100 Verified. Testing Truncate (Shrink)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("truncate trunc.txt 5`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 44
                     $buffer = ""
                }

                if ($stage -eq 44 -and $buffer -match "Truncated '.*trunc.txt' to 5 bytes") {
                     Write-Host "`n[TEST] Shrink Verified. Checking Content..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("cat trunc.txt`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 45
                     $buffer = ""
                }

                if ($stage -eq 45 -and $buffer -match "data") {
                     Write-Host "`n[TEST] Content Verified. Testing Sparse File (Large Truncate)..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("truncate sparse.bin 10240`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 46
                     $buffer = ""
                }

                if ($stage -eq 46 -and $buffer -match "Truncated '.*sparse.bin' to 10240 bytes") {
                     Write-Host "`n[TEST] Sparse Create Verified. Checking LS size..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("ls sparse.bin`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
                     $stage = 47
                     $buffer = ""
                }

                if ($stage -eq 47 -and $buffer -match "rw-.* 10240 .*sparse.bin") {
                     Write-Host "`n[TEST] Sparse Size Verified. Testing Sync..." -ForegroundColor Yellow
                     Start-Sleep -Milliseconds 500
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes("sync`r`n")
                     foreach ($b in $bytes) { $stream.WriteByte($b); $stream.Flush(); Start-Sleep -Milliseconds 10 }
                     
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
        } else {
            Start-Sleep -Milliseconds 10
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
