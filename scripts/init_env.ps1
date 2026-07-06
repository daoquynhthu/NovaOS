# NovaOS 开发环境初始化脚本 (PowerShell)

Write-Host "NovaOS Development Environment Setup" -ForegroundColor Cyan

# 1. 检查 Rust 环境
$rustc = Get-Command rustc -ErrorAction SilentlyContinue
if ($rustc) {
    Write-Host "[OK] Rust is installed." -ForegroundColor Green
} else {
    Write-Host "[ERR] Rust is missing! Please install via rustup.rs" -ForegroundColor Red
    exit 1
}

# 2. 安装目标架构 (x86_64-unknown-none)
Write-Host "Installing Rust target: x86_64-unknown-none..."
rustup target add x86_64-unknown-none

# 3. 检查 CMake
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if ($cmake) {
    Write-Host "[OK] CMake is installed." -ForegroundColor Green
} else {
    Write-Host "[ERR] CMake is missing!" -ForegroundColor Red
    exit 1
}

# 4. 检查 Python 依赖 (seL4 需要)
Write-Host "Checking Python dependencies for seL4..."
pip install sel4-deps

Write-Host "Setup complete! You can now run:" -ForegroundColor Cyan
Write-Host "  mkdir build"
Write-Host "  cd build"
Write-Host "  cmake -DKernelSel4Arch=x86_64 -DKernelPlatform=pc99 .."
Write-Host "  ninja"
