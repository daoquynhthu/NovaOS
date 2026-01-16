use core::fmt;

/// 简单的串口输出结构体
/// 注意：这是非线程安全的，仅用于 RootServer 单线程环境
pub struct SerialPort;

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.bytes() {
            // 1. Send to Debug Output (Syscall) - Safe and always works in debug build
            #[cfg(target_arch = "x86_64")]
            unsafe {
                 // seL4_SysDebugPutChar = -9
                 const SEL4_SYS_DEBUG_PUT_CHAR: isize = -9;
                 let sys_num: usize = SEL4_SYS_DEBUG_PUT_CHAR as usize;
                 let dest: usize = c as usize;
                 let info: usize = 0;
                 
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

            // 2. Send to Serial Port - Might fail if Port IO not ready
            // crate::serial::send_char(c as char);
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
