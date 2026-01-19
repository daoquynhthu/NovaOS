qemu-system-x86_64 `
    -kernel build/kernel/kernel32.elf `
    -initrd target/x86_64-unknown-none/release/rootserver `
    -serial file:serial.log `
    -m 512M `
    -cpu Nehalem `
    -no-reboot `
    -no-shutdown `
    -display none
