use core::slice;
use core::str;

pub struct Args {
    count: usize,
    current: usize,
    argv: *const *const u8,
}

impl Args {
    /// # Safety
    /// This function must be called with valid argc and argv from the process entry point.
    /// The argv array and strings pointed to must be valid for the lifetime of this iterator.
    pub unsafe fn new(count: usize, argv: *const *const u8) -> Self {
        Args {
            count,
            current: 0,
            argv,
        }
    }
}

impl Iterator for Args {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.count {
            return None;
        }

        unsafe {
            let s_ptr = *self.argv.add(self.current);
            let mut len = 0;
            while *s_ptr.add(len) != 0 {
                len += 1;
            }
            let s_slice = slice::from_raw_parts(s_ptr, len);
            self.current += 1;
            
            // We assume args are valid UTF-8 and live forever (on stack)
            // Transmute to 'static because stack args live for process duration
            let s = str::from_utf8(s_slice).ok()?;
            Some(core::mem::transmute(s))
        }
    }
}
