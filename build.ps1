# NovaOS 自动化构建脚本

$ErrorActionPreference = "Stop"

# 1. 配置参数
$BUILD_DIR = "build"
$ARCH = "x86_64"
$PLATFORM = "pc99"

# 2. 清理旧构建 (可选)
if (Test-Path $BUILD_DIR) {
    Write-Host "Cleaning build directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BUILD_DIR
}
New-Item -ItemType Directory -Force $BUILD_DIR | Out-Null

# 3. 运行 CMake 配置
Write-Host "Configuring CMake for seL4 ($ARCH/$PLATFORM)..." -ForegroundColor Cyan
Set-Location $BUILD_DIR

# 添加 LLVM 到 PATH
$env:PATH = "C:\Program Files\LLVM\bin;" + $env:PATH

# 注意：传递给 seL4 的标准 CMake 参数
cmake -DCMAKE_TOOLCHAIN_FILE="../kernel/seL4/llvm.cmake" `
      -DTRIPLE="x86_64-unknown-linux-gnu" `
      -DCMAKE_C_COMPILER="clang" `
      -DCMAKE_CXX_COMPILER="clang++" `
      -DCMAKE_ASM_COMPILER="clang" `
      -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" `
      -DKernelSel4Arch="$ARCH" `
      -DKernelPlatform="$PLATFORM" `
      -DPYTHON3="C:/Users/Lenovo/AppData/Local/Programs/Python/Python314/python.exe" `
      -DKernelVerificationBuild=OFF `
      -DKernelDebugBuild=ON `
      -DKernelPrinting=ON `
      -DKernelSupportPCID=OFF `
      -DLibSel4FunctionAttributes=inline `
      -G "Ninja" `
      ..

if ($LASTEXITCODE -ne 0) {
    Write-Host "CMake configuration failed!" -ForegroundColor Red
    exit 1
}

# 4. 执行构建
Write-Host "Building system..." -ForegroundColor Cyan
ninja

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Build success! Artifacts are in $BUILD_DIR" -ForegroundColor Green
Set-Location ..
