# NovaOS Build Script
$ErrorActionPreference = "Stop"

# Set up environment variables for seL4-sys build
Set-Location $PSScriptRoot
$root = $PSScriptRoot
$env:SEL4_OUT_DIR = "$root\build\kernel"
$env:SEL4_KERNEL_DIR = "$root\kernel\seL4"

Write-Host "SEL4_OUT_DIR: $env:SEL4_OUT_DIR"
Write-Host "SEL4_KERNEL_DIR: $env:SEL4_KERNEL_DIR"

# Build User App first
Write-Host "Building User App (Rust)..." -ForegroundColor Cyan
Set-Location "services/user_app"
cargo build --target x86_64-unknown-none --release
if ($LASTEXITCODE -ne 0) { Write-Error "User App build failed"; exit 1 }
Set-Location "../.."

Write-Host "Building RootServer (Rust)..." -ForegroundColor Cyan
Set-Location "services/rootserver"
cargo build --target x86_64-unknown-none --release
if ($LASTEXITCODE -ne 0) { Write-Error "Cargo build failed"; exit 1 }
Set-Location "../.."

# Verify Kernel exists
if (-not (Test-Path "build/kernel/kernel32.elf")) {
    Write-Error "Kernel (kernel32.elf) not found in build/kernel/. Please build the kernel first."
    exit 1
}

Write-Host "Build Complete!" -ForegroundColor Green
Write-Host "User App:   target/x86_64-unknown-none/release/user_app"
Write-Host "RootServer: target/x86_64-unknown-none/release/rootserver"
Write-Host "Kernel:     build/kernel/kernel32.elf"
