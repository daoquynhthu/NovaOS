use core::fmt;
use spin::Mutex;
use crate::syscall::sys_print;
use sel4_sys::seL4_CPtr;

static CONSOLE_EP: Mutex<Option<seL4_CPtr>> = Mutex::new(None);

pub fn init_console(ep: usize) {
    *CONSOLE_EP.lock() = Some(ep as seL4_CPtr);
}

pub struct DebugConsole;

impl DebugConsole {
    fn write_byte(&self, c: u8) {
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
    }
}

impl fmt::Write for DebugConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.bytes() {
            if c == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(c);
        }
        Ok(())
    }
}

pub struct UserConsole {
    ep: seL4_CPtr,
}

impl fmt::Write for UserConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        sys_print(self.ep, s);
        Ok(())
    }
}

pub fn print_impl(args: fmt::Arguments) {
    use fmt::Write;
    
    // Check if we have a registered user console endpoint
    // Note: We avoid holding the lock during the write to prevent deadlocks,
    // but we need the EP.
    let ep_opt = *CONSOLE_EP.lock();
    
    if let Some(ep) = ep_opt {
        let mut console = UserConsole { ep };
        let _ = console.write_fmt(args);
    } else {
        // Fallback to kernel debug console
        let _ = DebugConsole.write_fmt(args);
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::console::print_impl(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
