$ErrorActionPreference = "Stop"

# Set up environment variables for seL4-sys build
$root = Get-Location
$env:SEL4_OUT_DIR = "$root\build\kernel"
$env:SEL4_KERNEL_DIR = "$root\kernel\seL4"

Write-Host "Building RootServer..." -ForegroundColor Cyan
Set-Location "services/rootserver"

# Build Release
cargo build --target x86_64-unknown-none --release
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed"
    exit 1
}

Set-Location "../.."
$executable = "$PWD/target/x86_64-unknown-none/release/rootserver"

# Verify Kernel exists
if (-not (Test-Path "build/kernel/kernel32.elf")) {
    Write-Error "Kernel (kernel32.elf) not found in build/kernel/. Please build the kernel first."
    exit 1
}

Write-Host "Running QEMU for Testing..." -ForegroundColor Cyan

# Output file for QEMU
$outputFile = "$PWD/test_output.txt"
if (Test-Path $outputFile) { Remove-Item $outputFile }

# QEMU Path Selection
$qemu = "qemu-system-x86_64"
if (-not (Get-Command $qemu -ErrorAction SilentlyContinue)) {
    $commonPaths = @(
        "C:\Program Files\qemu\qemu-system-x86_64.exe",
        "C:\Program Files (x86)\qemu\qemu-system-x86_64.exe"
    )
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            $qemu = $path
            break
        }
    }
}

if (-not (Get-Command $qemu -ErrorAction SilentlyContinue) -and -not (Test-Path $qemu)) {
    Write-Error "QEMU not found! Please install QEMU or add it to your PATH."
    exit 1
}

Write-Host "Using QEMU: $qemu" -ForegroundColor Gray

# QEMU Arguments
$qemuArgs = @(
    "-kernel", "build/kernel/kernel32.elf",
    "-initrd", $executable,
    "-serial", "file:$outputFile",
    "-display", "none",
    "-m", "128M",
    "-cpu", "Haswell,+pdpe1gb",
    "-accel", "tcg,tb-size=64",
    # "-accel", "whpx",
    "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"
)

Write-Host "Command: $qemu $qemuArgs"

# Start QEMU in background
$process = Start-Process -FilePath $qemu -ArgumentList $qemuArgs -PassThru -NoNewWindow

$timeoutSeconds = 60
$startTime = Get-Date
$testPassed = $false

try {
    while (-not $process.HasExited) {
        if ((Get-Date) - $startTime -gt [TimeSpan]::FromSeconds($timeoutSeconds)) {
            Write-Warning "Test Timed Out!"
            break
        }

        if (Test-Path $outputFile) {
            try {
                $content = Get-Content $outputFile -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    if ($content -match "\[TEST\] PASSED") {
                        Write-Host "Found success marker!" -ForegroundColor Green
                        $testPassed = $true
                        break
                    }
                    if ($content -match "PANIC") {
                         Write-Host "Panic detected!" -ForegroundColor Red
                         break
                    }
                }
            } catch {}
        }
        Start-Sleep -Milliseconds 500
    }
} finally {
    if (-not $process.HasExited) {
        Stop-Process -InputObject $process -Force
    }
}

# Display Output
Write-Host "`n--- QEMU Output ---" -ForegroundColor Gray
if (Test-Path $outputFile) {
    Get-Content $outputFile
} else {
    Write-Host "No output generated."
}
Write-Host "-------------------`n"

if ($testPassed) {
    Write-Host "TEST RESULT: PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "TEST RESULT: FAILED" -ForegroundColor Red
    exit 1
}
