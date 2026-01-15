use core::fmt;

/// 简单的串口输出结构体
/// 注意：这是非线程安全的，仅用于 RootServer 单线程环境
pub struct SerialPort;

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.bytes() {
            // 调用 seL4 的调试打印系统调用
            // seL4_DebugPutChar 仅在 Debug 内核模式下可用
            // 在 Release 模式下，我们需要实现真正的串口驱动
            // Manually implement seL4_DebugPutChar because it is static inline
            // and not exported by bindgen.
            // Assumes x86_64 architecture.
            #[cfg(target_arch = "x86_64")]
            unsafe {
                 // seL4_SysDebugPutChar = -9 (defined in seL4/syscall.h)
                 // We hardcode it here because bindgen didn't export it or it's an enum.
                 const SEL4_SYS_DEBUG_PUT_CHAR: isize = -9;
                 let sys_num: usize = SEL4_SYS_DEBUG_PUT_CHAR as usize;
                 let dest: usize = c as usize;
                 let info: usize = 0;
                 
                 // Save rsp to r12 because syscall might clobber it (or we follow seL4 C stub convention).
                 // We use r12 instead of rbx because LLVM reserves rbx.
                 core::arch::asm!(
                    "mov r12, rsp",
                    "syscall",
                    "mov rsp, r12",
                    in("rdx") sys_num,
                    in("rdi") dest,
                    in("rsi") info,
                    out("rcx") _,
                    out("r11") _,
                    out("r12") _,
                 );
            }
        }
        Ok(())
    }
}

pub fn print_impl(args: fmt::Arguments) {
    use fmt::Write;
    let _ = SerialPort.write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::runtime::console::print_impl(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
