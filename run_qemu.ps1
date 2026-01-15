$QEMU = "C:\Program Files\qemu\qemu-system-x86_64.exe"
# Try kernel32.elf first (if converted), then kernel.elf
if (Test-Path "$PSScriptRoot\build\kernel\kernel32.elf") {
    $KERNEL = "$PSScriptRoot\build\kernel\kernel32.elf"
} elseif (Test-Path "$PSScriptRoot\build\kernel\kernel.elf") {
    $KERNEL = "$PSScriptRoot\build\kernel\kernel.elf"
} else {
    Write-Host "Kernel not found!" -ForegroundColor Red
    exit 1
}
# Check if built via CMake (build.ps1) or Cargo direct
if (Test-Path "$PSScriptRoot\build\cargo\x86_64-unknown-none\release\rootserver") {
    $ROOTSERVER = "$PSScriptRoot\build\cargo\x86_64-unknown-none\release\rootserver"
} else {
    $ROOTSERVER = "$PSScriptRoot\target\x86_64-unknown-none\release\rootserver"
}

Write-Host "Starting QEMU..."
& $QEMU -cpu IvyBridge,+pdpe1gb -kernel $KERNEL -initrd $ROOTSERVER -m 256 -nographic -serial file:serial.log -d guest_errors
