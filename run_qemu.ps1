$root = $PSScriptRoot
$buildDir = if ($env:NOVA_BUILD_DIR) { $env:NOVA_BUILD_DIR } else { "build" }
$kernelElf = Join-Path (Join-Path $root $buildDir) "kernel/kernel32.elf"
$rootserver = Join-Path $root "target/x86_64-unknown-none/release/rootserver"
$serialLog = Join-Path $root "serial.log"
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
    "Nehalem"
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
    "-initrd", $rootserver,
    "-serial", "file:$serialLog",
    "-m", "512M"
)

if ($qemuMachineOverride) {
    $qemuArgs += @("-machine", $qemuMachineOverride)
}

$qemuArgs += @(
    "-cpu", $cpuModel,
    "-accel", $accel,
    "-no-reboot",
    "-no-shutdown",
    "-display", "none"
)

& qemu-system-x86_64 @qemuArgs
