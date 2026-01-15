# NovaOS Build Script
$ErrorActionPreference = "Stop"

# Set up environment variables for seL4-sys build
$root = Get-Location
$env:SEL4_OUT_DIR = "$root\build\kernel"
$env:SEL4_KERNEL_DIR = "$root\kernel\seL4"

Write-Host "SEL4_OUT_DIR: $env:SEL4_OUT_DIR"
Write-Host "SEL4_KERNEL_DIR: $env:SEL4_KERNEL_DIR"

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
Write-Host "RootServer: services/rootserver/target/x86_64-unknown-none/release/rootserver"
Write-Host "Kernel:     build/kernel/kernel32.elf"
