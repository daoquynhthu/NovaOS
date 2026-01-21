
use crate::drivers::keyboard::Key;
use alloc::string::ToString;
use libnova::cap::cap_rights_new;
use crate::memory::{SlotAllocator, UntypedAllocator, FrameAllocator};
use crate::tests;
use sel4_sys::seL4_BootInfo;

const MAX_CMD_LEN: usize = 64;
const HISTORY_LEN: usize = 16;

const COMMANDS: &[&str] = &[
    "help", "clear", "echo", "cat", "whoami", "status", "bootinfo", "alloc", "meminfo",
    "ps", "ls", "kill", "exec", "history", "post", "runhello", "cd", "mkdir", "rm", "cp", "mv", "touch", "pwd",
    "renice", "pci", "date", "disk_read", "disk_write", "mkfs", "mount", "sync", "write", "encrypt", "decrypt", "ln", "chmod", "chown",
    "env", "export", "unset"
];

pub struct Shell {
    buffer: [char; MAX_CMD_LEN],
    len: usize,
    cursor: usize,
    boot_info: *const seL4_BootInfo,
    allocator: *mut UntypedAllocator,
    slots: *mut SlotAllocator,
    frame_allocator: *mut FrameAllocator,
    history: [[char; MAX_CMD_LEN]; HISTORY_LEN],
    history_lens: [usize; HISTORY_LEN],
    history_count: usize,
    history_head: usize,
    history_view: Option<usize>,
    draft: [char; MAX_CMD_LEN],
    draft_len: usize,
    draft_cursor: usize,
    draft_valid: bool,
    syscall_ep_cap: sel4_sys::seL4_CPtr,
    cwd: alloc::string::String,
    env_vars: alloc::collections::BTreeMap<alloc::string::String, alloc::string::String>,
}

impl Shell {
    pub fn new() -> Self {
        let mut env_vars = alloc::collections::BTreeMap::new();
        env_vars.insert("PATH".into(), "/bin".into());
        env_vars.insert("HOME".into(), "/".into());
        env_vars.insert("TERM".into(), "nova-term".into());

        Shell {
            buffer: ['\0'; MAX_CMD_LEN],
            len: 0,
            cursor: 0,
            boot_info: core::ptr::null(),
            allocator: core::ptr::null_mut(),
            slots: core::ptr::null_mut(),
            frame_allocator: core::ptr::null_mut(),
            history: [['\0'; MAX_CMD_LEN]; HISTORY_LEN],
            history_lens: [0; HISTORY_LEN],
            history_count: 0,
            history_head: 0,
            history_view: None,
            draft: ['\0'; MAX_CMD_LEN],
            draft_len: 0,
            draft_cursor: 0,
            draft_valid: false,
            syscall_ep_cap: 0,
            cwd: alloc::string::String::from("/"),
            env_vars,
        }
    }

    fn format_mode(mode: u16) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        // User
        s.push(if mode & 0o400 != 0 { 'r' } else { '-' });
        s.push(if mode & 0o200 != 0 { 'w' } else { '-' });
        s.push(if mode & 0o100 != 0 { 'x' } else { '-' });
        // Group
        s.push(if mode & 0o040 != 0 { 'r' } else { '-' });
        s.push(if mode & 0o020 != 0 { 'w' } else { '-' });
        s.push(if mode & 0o010 != 0 { 'x' } else { '-' });
        // Other
        s.push(if mode & 0o004 != 0 { 'r' } else { '-' });
        s.push(if mode & 0o002 != 0 { 'w' } else { '-' });
        s.push(if mode & 0o001 != 0 { 'x' } else { '-' });
        s
    }

    fn format_time(ts: u64) -> alloc::string::String {
        let seconds_per_day = 86400;
        let mut days = ts / seconds_per_day;
        let mut seconds = ts % seconds_per_day;
        
        let hour = seconds / 3600;
        seconds %= 3600;
        let minute = seconds / 60;
        let second = seconds % 60;
        
        let mut year = 1970;
        loop {
            let days_in_year = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) { 366 } else { 365 };
            if days >= days_in_year {
                days -= days_in_year;
                year += 1;
            } else {
                break;
            }
        }
        
        let days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        
        let mut month = 1;
        for i in 1..=12 {
            let mut d = days_in_month[i];
            if i == 2 && is_leap { d = 29; }
            if days >= d {
                days -= d;
                month += 1;
            } else {
                break;
            }
        }
        let day = days + 1;
        
        alloc::format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hour, minute, second)
    }

    pub fn init(
        &mut self,
        boot_info: &seL4_BootInfo,
        allocator: &mut UntypedAllocator,
        slots: &mut SlotAllocator,
        frame_allocator: &mut FrameAllocator,
        syscall_ep_cap: sel4_sys::seL4_CPtr,
    ) {
        self.boot_info = boot_info as *const seL4_BootInfo;
        self.allocator = allocator as *mut UntypedAllocator;
        self.slots = slots as *mut SlotAllocator;
        self.frame_allocator = frame_allocator as *mut FrameAllocator;
        self.syscall_ep_cap = syscall_ep_cap;
        println!("\n[SHELL] Ready. Type 'help' for commands.");
        self.print_prompt();
    }

    fn print_prompt(&self) {
        print!("\x1b[1;32mNovaOS:{}>\x1b[0m ", self.cwd);
    }

    pub fn on_key(&mut self, k: Key) {
        match k {
            Key::Enter => {
                println!();
                self.history_view = None;
                self.draft_valid = false;
                self.execute_command();
                self.clear_line();
                self.print_prompt();
            }
            Key::Backspace => {
                self.history_view = None;
                self.draft_valid = false;
                if self.cursor == 0 {
                    return;
                }
                self.cursor -= 1;
                self.shift_left_from(self.cursor);
                print!("\x1b[D");
                self.redraw_from(self.cursor);
            }
            Key::Delete => {
                self.history_view = None;
                self.draft_valid = false;
                if self.cursor >= self.len {
                    return;
                }
                self.shift_left_from(self.cursor);
                self.redraw_from(self.cursor);
            }
            Key::Left => {
                if self.cursor == 0 {
                    return;
                }
                self.cursor -= 1;
                print!("\x1b[D");
            }
            Key::Right => {
                if self.cursor >= self.len {
                    return;
                }
                self.cursor += 1;
                print!("\x1b[C");
            }
            Key::Home => {
                if self.cursor == 0 {
                    return;
                }
                let n = self.cursor;
                self.cursor = 0;
                print!("\x1b[{}D", n);
            }
            Key::End => {
                if self.cursor >= self.len {
                    return;
                }
                let n = self.len - self.cursor;
                self.cursor = self.len;
                print!("\x1b[{}C", n);
            }
            Key::Tab => self.handle_tab(),
            Key::Up => self.history_up(),
            Key::Down => self.history_down(),
            Key::PageUp | Key::PageDown => {}
            Key::Esc => {
                // Clear current line
                self.history_view = None;
                self.draft_valid = false;
                self.move_cursor_to_start();
                print!("\x1b[K"); // Clear line
                self.len = 0;
                self.cursor = 0;
                for i in 0..MAX_CMD_LEN {
                    self.buffer[i] = '\0';
                }
            }
            Key::F1 => {
                println!();
                println!("Available commands:");
                for cmd in COMMANDS {
                    print!("{} ", cmd);
                }
                println!();
                self.print_prompt();
                self.redraw_from(0);
            }
            Key::F2 | Key::F3 | Key::F4 | Key::F5 | Key::F6 | Key::F7 | Key::F8 | Key::F9 | Key::F10 | Key::F11 | Key::F12 => {}
            Key::Unknown(_) => {}
            Key::Char(c) => {
                self.history_view = None;
                self.draft_valid = false;
                match c {
                    '\x01' => self.ctrl_home(),
                    '\x05' => self.ctrl_end(),
                    '\x0b' => self.ctrl_kill_to_end(),
                    '\x15' => self.ctrl_kill_to_start(),
                    _ => self.insert_char(c),
                }
            }
        }
    }

    fn ctrl_home(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let n = self.cursor;
        self.cursor = 0;
        print!("\x1b[{}D", n);
    }

    fn ctrl_end(&mut self) {
        if self.cursor >= self.len {
            return;
        }
        let n = self.len - self.cursor;
        self.cursor = self.len;
        print!("\x1b[{}C", n);
    }

    fn ctrl_kill_to_end(&mut self) {
        if self.cursor >= self.len {
            return;
        }
        for i in self.cursor..self.len {
            self.buffer[i] = '\0';
        }
        self.len = self.cursor;
        print!("\x1b[K");
    }

    fn ctrl_kill_to_start(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let cut = self.cursor;
        let remaining = self.len - cut;
        for i in 0..remaining {
            self.buffer[i] = self.buffer[cut + i];
        }
        for i in remaining..self.len {
            self.buffer[i] = '\0';
        }
        self.len = remaining;
        self.move_cursor_to_start();
        print!("\x1b[K");
        for i in 0..self.len {
            print!("{}", self.buffer[i]);
        }
        self.cursor = self.len;
        self.move_cursor_to_start();
    }

    fn handle_tab(&mut self) {
        let (word_start, word_end) = self.get_word_at_cursor();
        if word_end != self.cursor {
            return;
        }

        let prefix_len = word_end - word_start;
        
        let is_first_word = self.is_first_word(word_start);
        
        let mut matches: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
        
        if is_first_word {
            for &cmd in COMMANDS {
                if self.word_starts_with_str(word_start, cmd) {
                    matches.push(alloc::string::String::from(cmd));
                }
            }
        } else {
             if self.command_is("exec") {
                 if let Some(files) = crate::vfs::VFS.lock().as_ref().and_then(|fs| fs.list_dir("/bin").ok()) {
                     for file in files {
                         if self.word_starts_with_str(word_start, &file) {
                             matches.push(file);
                         }
                     }
                 }
             } else if self.command_is("ls") || self.command_is("cat") || self.command_is("cd") || self.command_is("rm") || self.command_is("touch") {
                  if let Some(files) = crate::vfs::VFS.lock().as_ref().and_then(|fs| fs.list_dir(&self.cwd).ok()) {
                       for file in files {
                           if self.word_starts_with_str(word_start, &file) {
                               matches.push(file);
                           }
                       }
                  }
             }
        }
        
        if matches.len() == 1 {
            let completion = &matches[0];
            for c in completion.chars().skip(prefix_len) {
                self.insert_char(c);
            }
            self.insert_char(' ');
        } else if matches.len() > 1 {
             println!();
             for m in &matches {
                 print!("{}  ", m);
             }
             println!();
             self.print_prompt();
             self.redraw_from(0);
             if self.cursor > 0 {
                 print!("\x1b[{}C", self.cursor);
             }
        }
    }

    fn get_word_at_cursor(&self) -> (usize, usize) {
        let end = self.cursor;
        let mut start = end;
        while start > 0 {
            let c = self.buffer[start - 1];
            if c == ' ' || c == '\t' {
                break;
            }
            start -= 1;
        }
        (start, end)
    }

    fn is_first_word(&self, word_start: usize) -> bool {
        for i in 0..word_start {
            let c = self.buffer[i];
            if c != ' ' && c != '\t' {
                return false;
            }
        }
        true
    }

    fn word_starts_with_str(&self, start: usize, s: &str) -> bool {
        let len = s.len();
        let buf_len = self.cursor - start;
        if buf_len > len {
            return false;
        }
        for (i, c) in s.chars().take(buf_len).enumerate() {
            if self.buffer[start + i] != c {
                return false;
            }
        }
        true
    }
    
    fn command_is(&self, cmd: &str) -> bool {
        if let Some((s, e)) = self.trim_range() {
             let (ws, we, _) = self.split_word(s, e);
             return self.word_eq(ws, we, cmd);
        }
        false
    }

    fn insert_char(&mut self, c: char) {
        if self.len >= MAX_CMD_LEN {
            return;
        }
        self.shift_right_from(self.cursor);
        self.buffer[self.cursor] = c;
        print!("{}", c);
        self.cursor += 1;
        self.len += 1;
        for i in self.cursor..self.len {
            print!("{}", self.buffer[i]);
        }
        let back = self.len - self.cursor;
        if back != 0 {
            print!("\x1b[{}D", back);
        }
    }

    fn history_up(&mut self) {
        if self.history_count == 0 {
            return;
        }

        if self.history_view.is_none() {
            self.save_draft();
            self.history_view = Some(self.history_count - 1);
            self.load_history_view();
            return;
        }

        if let Some(pos) = self.history_view {
            if pos == 0 {
                return;
            }
            self.history_view = Some(pos - 1);
            self.load_history_view();
        }
    }

    fn history_down(&mut self) {
        if self.history_count == 0 {
            return;
        }

        let Some(pos) = self.history_view else {
            return;
        };

        if pos + 1 >= self.history_count {
            self.restore_draft();
            self.history_view = None;
            self.draft_valid = false;
            return;
        }

        self.history_view = Some(pos + 1);
        self.load_history_view();
    }

    fn save_draft(&mut self) {
        if self.draft_valid {
            return;
        }
        for i in 0..self.len {
            self.draft[i] = self.buffer[i];
        }
        for i in self.len..MAX_CMD_LEN {
            self.draft[i] = '\0';
        }
        self.draft_len = self.len;
        self.draft_cursor = self.cursor;
        self.draft_valid = true;
    }

    fn restore_draft(&mut self) {
        if !self.draft_valid {
            return;
        }
        let draft = self.draft;
        let draft_len = self.draft_len;
        let draft_cursor = self.draft_cursor;
        self.replace_line(&draft, draft_len, draft_cursor);
    }

    fn load_history_view(&mut self) {
        let Some(pos) = self.history_view else {
            return;
        };
        let (ring_idx, len) = self.history_pos_to_ring(pos);
        let line = self.history[ring_idx];
        self.replace_line(&line, len, len);
    }

    fn history_pos_to_ring(&self, pos: usize) -> (usize, usize) {
        let oldest = if self.history_count < HISTORY_LEN {
            0
        } else {
            self.history_head
        };
        let idx = (oldest + pos) % HISTORY_LEN;
        (idx, self.history_lens[idx])
    }

    fn shift_right_from(&mut self, start: usize) {
        for i in (start..self.len).rev() {
            self.buffer[i + 1] = self.buffer[i];
        }
    }

    fn shift_left_from(&mut self, start: usize) {
        for i in start..self.len.saturating_sub(1) {
            self.buffer[i] = self.buffer[i + 1];
        }
        if self.len != 0 {
            self.len -= 1;
            self.buffer[self.len] = '\0';
        }
    }

    fn redraw_from(&self, start: usize) {
        for i in start..self.len {
            print!("{}", self.buffer[i]);
        }
        print!(" ");
        let back = self.len.saturating_sub(start) + 1;
        if back != 0 {
            print!("\x1b[{}D", back);
        }
    }

    fn replace_line(&mut self, src: &[char; MAX_CMD_LEN], len: usize, cursor: usize) {
        self.move_cursor_to_start();
        print!("\x1b[K");

        let mut n = len;
        if n > MAX_CMD_LEN {
            n = MAX_CMD_LEN;
        }

        for (i, c) in src.iter().copied().enumerate().take(n) {
            self.buffer[i] = c;
            print!("{}", c);
        }
        self.buffer[n..].fill('\0');

        self.len = n;
        let mut c = cursor;
        if c > n {
            c = n;
        }
        self.cursor = n;
        if n > c {
            print!("\x1b[{}D", n - c);
            self.cursor = c;
        }
    }

    fn move_cursor_to_start(&mut self) {
        if self.cursor != 0 {
            print!("\x1b[{}D", self.cursor);
            self.cursor = 0;
        }
    }

    fn clear_line(&mut self) {
        for i in 0..self.len {
            self.buffer[i] = '\0';
        }
        self.len = 0;
        self.cursor = 0;
    }

    fn resolve_path(&self, path: &str) -> alloc::string::String {
        let full_path = if path.starts_with('/') {
            alloc::string::String::from(path)
        } else {
            let mut s = self.cwd.clone();
            if !s.ends_with('/') { s.push('/'); }
            s.push_str(path);
            s
        };

        let mut components = alloc::vec::Vec::new();
        for part in full_path.split('/') {
            if part.is_empty() || part == "." { continue; }
            if part == ".." {
                components.pop();
            } else {
                components.push(part);
            }
        }

        let mut res = alloc::string::String::from("/");
        for (i, part) in components.iter().enumerate() {
            if i > 0 { res.push('/'); }
            res.push_str(part);
        }
        res
    }

    fn execute_command(&mut self) {
        let Some((start, end)) = self.trim_range() else {
            return;
        };

        self.history_push(start, end);

        let (word_start, word_end, rest_start) = self.split_word(start, end);

        if self.word_eq(word_start, word_end, "help") {
            println!("Available commands:");
            println!("  help      - Show this help");
            println!("  clear     - Clear screen");
            println!("  echo      - Echo text");
            println!("  cat       - Print file content");
            println!("  cd        - Change directory");
            println!("  mkdir     - Create directory");
            println!("  touch     - Create empty file");
            println!("  ls        - List directory");
            println!("  rm        - Remove file/directory");
            println!("  cp        - Copy file");
            println!("  mv        - Move/Rename file");
            println!("  pwd       - Print working directory");
            println!("  whoami    - Show user info");
            println!("  status    - Show system status");
            println!("  bootinfo  - Show seL4 BootInfo summary");
            println!("  alloc     - Show allocator summary");
            println!("  meminfo   - Show memory usage summary");
            println!("  ps        - List tracked processes");
            println!("  ls        - List available files");
            println!("  kill      - Kill a process by PID");
            println!("  exec      - Execute a program (e.g. exec hello)");
            println!("  history   - Show recent commands");
            println!("  post      - Run POST tests again");
            println!("  runhello  - Run minimal user-mode program");
            println!("  shutdown  - Power off the system");
            println!("  renice    - Change process priority (renice <pid> <prio>)");
            println!("  pci       - List PCI devices");
            println!("  encrypt   - Encrypt a file (encrypt <file>)");
            println!("  decrypt   - Decrypt a file (removes encryption flag)");
            println!("  env       - List environment variables");
            println!("  export    - Set environment variable");
            println!("  unset     - Unset environment variable");
        } else if self.word_eq(word_start, word_end, "clear") {
            print!("\x1b[2J\x1b[1;1H");
        } else if self.word_eq(word_start, word_end, "env") {
            for (k, v) in &self.env_vars {
                println!("{}={}", k, v);
            }
        } else if self.word_eq(word_start, word_end, "export") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: export KEY=VALUE");
            } else {
                let s = &self.buffer[rest_start..end];
                let s_str = s.iter().collect::<alloc::string::String>();
                if let Some(idx) = s_str.find('=') {
                    let key = &s_str[..idx];
                    let val = &s_str[idx+1..];
                    self.env_vars.insert(key.into(), val.into());
                } else {
                    println!("Usage: export KEY=VALUE");
                }
            }
        } else if self.word_eq(word_start, word_end, "unset") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: unset KEY");
            } else {
                let s = &self.buffer[rest_start..end];
                let key = s.iter().collect::<alloc::string::String>();
                self.env_vars.remove(&key);
            }
        } else if self.word_eq(word_start, word_end, "pci") {
            crate::arch::pci::init();
        } else if self.word_eq(word_start, word_end, "disk_read") {
            let args_len = end - rest_start;
            if args_len == 0 {
                println!("Usage: disk_read <lba> <sectors>");
            } else {
                 let mut i = rest_start;
                 while i < end && self.buffer[i] == ' ' { i += 1; }
                 
                 let mut lba = 0;
                 while i < end && self.buffer[i].is_ascii_digit() {
                     lba = lba * 10 + (self.buffer[i] as usize - '0' as usize);
                     i += 1;
                 }
                 
                 while i < end && self.buffer[i] == ' ' { i += 1; }
                 
                 let mut sectors = 0;
                 while i < end && self.buffer[i].is_ascii_digit() {
                     sectors = sectors * 10 + (self.buffer[i] as usize - '0' as usize);
                     i += 1;
                 }
                 
                 if sectors == 0 { sectors = 1; }
                 
                 println!("Reading Disk: LBA={}, Sectors={}", lba, sectors);
                 let drv = crate::drivers::ata::AtaDriver::new(0x1F0);
                 match drv.read_sectors(lba as u32, sectors as u8) {
                     Ok(data) => {
                         println!("Read {} bytes.", data.len());
                         for (idx, byte) in data.iter().enumerate() {
                             if idx % 16 == 0 {
                                 print!("\n{:04x}: ", idx);
                             }
                             print!("{:02x} ", byte);
                         }
                         println!();
                         // Print ASCII
                         for byte in data.iter() {
                             let c = *byte as char;
                             if c.is_ascii_graphic() || c == ' ' {
                                 print!("{}", c);
                             } else {
                                 print!(".");
                             }
                         }
                         println!();
                     },
                     Err(e) => println!("Disk Read Error: {}", e),
                 }
            }
        } else if self.word_eq(word_start, word_end, "disk_write") {
             let args_len = end - rest_start;
             if args_len == 0 {
                 println!("Usage: disk_write <lba> <data_string>");
             } else {
                 let mut i = rest_start;
                 while i < end && self.buffer[i] == ' ' { i += 1; }
                 
                 let mut lba = 0;
                 while i < end && self.buffer[i].is_ascii_digit() {
                     lba = lba * 10 + (self.buffer[i] as usize - '0' as usize);
                     i += 1;
                 }
                 
                 while i < end && self.buffer[i] == ' ' { i += 1; }
                 
                 let mut data = alloc::vec::Vec::new();
                 while i < end {
                     data.push(self.buffer[i] as u8);
                     i += 1;
                 }
                 
                 // Pad to 512
                 while data.len() < 512 {
                     data.push(0);
                 }
                 
                 println!("Writing Disk: LBA={} DataLen={}", lba, data.len());
                 let drv = crate::drivers::ata::AtaDriver::new(0x1F0);
                 match drv.write_sectors(lba as u32, &data) {
                     Ok(_) => println!("Write Success."),
                     Err(e) => println!("Write Error: {}", e),
                 }
             }
        } else if self.word_eq(word_start, word_end, "mkfs") {
            let args_len = end - rest_start;
            if args_len == 0 {
                println!("Usage: mkfs <total_blocks>");
            } else {
                let mut i = rest_start;
                while i < end && self.buffer[i] == ' ' { i += 1; }
                let mut total_blocks = 0;
                while i < end && self.buffer[i].is_ascii_digit() {
                    total_blocks = total_blocks * 10 + (self.buffer[i] as usize - '0' as usize);
                    i += 1;
                }
                
                if total_blocks < 100 {
                     println!("Total blocks must be at least 100");
                } else {
                     println!("Formatting disk with NovaFS ({} blocks)...", total_blocks);
                     let drv = alloc::sync::Arc::new(crate::drivers::ata::AtaDriver::new(0x1F0));
                     let fs = crate::fs::novafs::NovaFS::format(drv, 0, total_blocks as u32);
                     *crate::fs::DISK_FS.lock() = Some(alloc::sync::Arc::new(fs));
                     println!("Format successful! Mounted as root.");
                }
            }
        } else if self.word_eq(word_start, word_end, "mount") {
             println!("Mounting NovaFS...");
             let drv = alloc::sync::Arc::new(crate::drivers::ata::AtaDriver::new(0x1F0));
             match crate::fs::novafs::NovaFS::new(drv, 0) {
                 Ok(fs) => {
                     *crate::fs::DISK_FS.lock() = Some(alloc::sync::Arc::new(fs));
                     println!("Mount successful.");
                 },
                 Err(e) => {
                     println!("Mount failed: {}", e);
                 }
             }

        } else if self.word_eq(word_start, word_end, "sync") {
            let fs_lock = crate::fs::DISK_FS.lock();
            if let Some(fs) = fs_lock.as_ref() {
                match fs.sync() {
                    Ok(_) => println!("FileSystem synced."),
                    Err(e) => println!("sync failed: {}", e),
                }
            } else {
                println!("sync: Filesystem not mounted");
            }

        } else if self.word_eq(word_start, word_end, "date") {
            let rtc = crate::drivers::rtc::RtcDriver::new();
            let (day, month, year) = rtc.read_date();
            let (hour, minute, second) = rtc.read_time();
            println!("Date: {:04}-{:02}-{:02}", year, month, day);
            println!("Time: {:02}:{:02}:{:02}", hour, minute, second);
        } else if self.word_eq(word_start, word_end, "whoami") {
            println!("root");
        } else if self.word_eq(word_start, word_end, "status") {
            println!("System: NovaOS v0.0.1-alpha");
            println!("Mode:   x86_64 Long Mode");
            println!("Driver: Keyboard, Serial(COM1), ACPI, IOAPIC");
        } else if self.word_eq(word_start, word_end, "shutdown") {
            println!("Shutting down system...");
            crate::acpi::shutdown();
        } else if self.word_eq(word_start, word_end, "bootinfo") {
            if self.boot_info.is_null() {
                println!("BootInfo: unavailable");
            } else {
                let bi = unsafe { &*self.boot_info };
                println!("[INFO] BootInfo Addr: {:p}", bi);
                println!("[INFO] IPC Buffer: {:p}", bi.ipcBuffer);
                println!("[INFO] Empty Slots: {} - {}", bi.empty.start, bi.empty.end);
                println!("[INFO] Untyped Slots: {} - {}", bi.untyped.start, bi.untyped.end);
                println!("[INFO] Untyped Memory: {} slots", bi.untyped.end - bi.untyped.start);
                println!("[INFO] CNode Size: {} bits", bi.initThreadCNodeSizeBits);
            }
        } else if self.word_eq(word_start, word_end, "alloc") {
            if self.boot_info.is_null() || self.allocator.is_null() {
                println!("Allocator: unavailable");
            } else {
                unsafe { (&*self.allocator).print_info(&*self.boot_info) };
            }
        } else if self.word_eq(word_start, word_end, "meminfo") {
            if self.boot_info.is_null() || self.allocator.is_null() || self.slots.is_null() {
                println!("meminfo: unavailable");
            } else {
                let bi = unsafe { &*self.boot_info };
                let slots = unsafe { &*self.slots };
                let alloc = unsafe { &*self.allocator };

                let (total_slots, used_slots, free_slots) = slots.stats();
                let (total_untyped, ram_untyped, used_bytes, total_bytes, last_used) =
                    alloc.stats(bi);

                println!("[MEM] CSpace Slots: total={}, used={}, free={}", total_slots, used_slots, free_slots);
                println!("[MEM] Untyped Caps: total={}, ram={}", total_untyped, ram_untyped);
                println!("[MEM] RAM Untyped Usage: used={} bytes, total={} bytes", used_bytes, total_bytes);
                println!("[MEM] Untyped LastUsedIdx: {}", last_used);
            }
        } else if self.word_eq(word_start, word_end, "ps") {
            use crate::process::get_process_manager;
            let pm = get_process_manager();
            let mut any = false;
            println!("PID  PPID State        Name             Heap       Frames Prio");
            println!("----------------------------------------------------------------");
            for (pid, slot) in pm.processes.iter().enumerate() {
                if let Some(p) = slot {
                    any = true;
                    print!("{:<4} {:<4} ", pid, p.ppid);
                    
                    let state_str = match p.state {
                        crate::process::ProcessState::Created => "Created",
                        crate::process::ProcessState::Loaded => "Loaded",
                        crate::process::ProcessState::Configured => "Configured",
                        crate::process::ProcessState::Running => "Running",
                        crate::process::ProcessState::Sleeping => "Sleeping",
                        crate::process::ProcessState::Suspended => "Suspended",
                        crate::process::ProcessState::BlockedOnRecv => "BlockedRecv",
                        crate::process::ProcessState::BlockedOnInput => "BlockedInput",
                        crate::process::ProcessState::BlockedOnWait => "BlockedWait",
                        crate::process::ProcessState::Terminated => "Terminated",
                    };
                    print!("{:<12} {:<16} {:<10x} {:<6} {}", 
                        state_str,
                        p.name,
                        p.heap_brk,
                        p.mapped_frames.len(),
                        p.priority
                    );
                    println!();
                }
            }
            if !any {
                println!("No processes tracked.");
            }
        } else if self.word_eq(word_start, word_end, "kill") {
            let pid_str_len = end - rest_start;
            if pid_str_len == 0 {
                println!("Usage: kill <pid>");
            } else {
                let mut pid = 0;
                let mut valid = true;
                // Simple parsing
                for i in rest_start..end {
                    let c = self.buffer[i];
                    if c.is_ascii_digit() {
                         pid = pid * 10 + (c as usize - '0' as usize);
                    } else {
                        valid = false;
                        break;
                    }
                }
                
                if !valid {
                    println!("Invalid PID");
                } else {
                    use crate::process::get_process_manager;
                    let mut pm = get_process_manager();
                    
                    if self.slots.is_null() || self.frame_allocator.is_null() {
                        println!("Error: System resources unavailable");
                    } else {
                        let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as sel4_sys::seL4_CPtr;
                        let slots = unsafe { &mut *self.slots };
                        let frame_allocator = unsafe { &mut *self.frame_allocator };
                        
                        // Use exit_process to properly handle parent notification and cleanup
                        match pm.exit_process(pid, -9, root_cnode, slots, frame_allocator) {
                            Ok(_) => println!("Process {} killed (signal -9).", pid),
                            Err(e) => println!("Failed to kill process {}: {:?}", pid, e),
                        }
                    }
                }
            }
        } else if self.word_eq(word_start, word_end, "renice") {
            let args_len = end - rest_start;
            if args_len == 0 {
                println!("Usage: renice <pid> <priority>");
            } else {
                // Manual parsing for <pid> <priority>
                let mut space_idx = None;
                for i in rest_start..end {
                    if self.buffer[i] == ' ' {
                        space_idx = Some(i);
                        break;
                    }
                }

                if let Some(sp) = space_idx {
                    let mut pid = 0;
                    let mut valid_pid = true;
                    for i in rest_start..sp {
                        let c = self.buffer[i];
                        if c.is_ascii_digit() {
                            pid = pid * 10 + (c as u32 as usize - '0' as u32 as usize);
                        } else {
                            valid_pid = false;
                            break;
                        }
                    }
                    
                    let mut prio = 0;
                    let mut valid_prio = true;
                    // skip extra spaces?
                    let mut prio_start = sp + 1;
                    while prio_start < end && self.buffer[prio_start] == ' ' {
                        prio_start += 1;
                    }

                    for i in prio_start..end {
                        let c = self.buffer[i];
                        if c.is_ascii_digit() {
                            prio = prio * 10 + (c as u32 as usize - '0' as u32 as usize);
                        } else {
                            valid_prio = false;
                            break;
                        }
                    }

                    if valid_pid && valid_prio {
                        use crate::process::get_process_manager;
                        let mut pm = get_process_manager();
                        if let Some(p) = pm.get_process_mut(pid) {
                            // Authority is Root TCB
                            let auth = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadTCB as usize;
                            match p.set_priority(auth.try_into().unwrap(), (prio as usize).try_into().unwrap()) {
                                Ok(_) => println!("Process {} priority set to {}", pid, prio),
                                Err(e) => println!("Failed to set priority: {:?}", e),
                            }
                        } else {
                            println!("Process {} not found.", pid);
                        }
                    } else {
                        println!("Invalid PID or Priority");
                    }
                } else {
                    println!("Usage: renice <pid> <priority>");
                }
            }
        } else if self.word_eq(word_start, word_end, "exec") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: exec <filename> [args...]");
            } else {
                let full_line = &self.buffer[rest_start..end];
                let full_line_str = full_line.iter().collect::<alloc::string::String>();
                let parts: alloc::vec::Vec<&str> = full_line_str.split_whitespace().collect();

                if let Some(filename) = parts.first() {
                    let args = parts.as_slice();
                    let path_str = self.resolve_path(filename);
                    
                    let mut final_data = None;
                    {
                        let vfs_lock = crate::vfs::VFS.lock();
                        if let Some(fs) = vfs_lock.as_ref() {
                            if let Ok(data) = fs.read_file(&path_str) {
                                final_data = Some(data);
                            } else if !path_str.contains("/bin/") {
                                 let bin_path = alloc::format!("/bin/{}", filename);
                                 if let Ok(data) = fs.read_file(&bin_path) {
                                     final_data = Some(data);
                                 }
                            }
                        }
                    }

                    if let Some(data) = final_data {
                        println!("Executing '{}' with args {:?}...", filename, args);
                        
                        let env_vec: alloc::vec::Vec<alloc::string::String> = self.env_vars.iter()
                            .map(|(k, v)| alloc::format!("{}={}", k, v))
                            .collect();
                        let env_slice: alloc::vec::Vec<&str> = env_vec.iter().map(|s| s.as_str()).collect();
                        
                        self.spawn_process(filename, &data, args, &env_slice);
                    } else {
                         println!("exec: {}: No such file or directory", path_str);
                    }
                } else {
                    println!("Usage: exec <filename> [args...]");
                }
            }
        } else if self.word_eq(word_start, word_end, "encrypt") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: encrypt <file>");
            } else {
                let filename = self.buffer[rest_start..end].iter().collect::<alloc::string::String>();
                println!("DEBUG: encrypt command for '{}'", filename);
                let path_str = self.resolve_path(&filename);
                println!("DEBUG: resolved path '{}'", path_str);
                let vfs_lock = crate::vfs::VFS.lock();
                if let Some(fs) = vfs_lock.as_ref() {
                    match fs.resolve_path("/", &path_str) {
                        Ok(inode) => {
                             // Read current flags first
                             match inode.control(1, 0) {
                                 Ok(flags) => {
                                    println!("DEBUG: encrypt command read flags: 0x{:x}", flags);
                                    // Set Encrypted bit (1)
                                    match inode.control(2, flags | 1) {
                                         Ok(_) => println!("File '{}' encrypted.", filename),
                                         Err(e) => println!("Failed to encrypt: {}", e),
                                     }
                                 },
                                 Err(e) => println!("Failed to get flags: {}", e),
                             }
                        },
                        Err(e) => println!("encrypt: {}: {}", filename, e),
                    }
                } else {
                    println!("encrypt: VFS not mounted");
                }
            }
        } else if self.word_eq(word_start, word_end, "decrypt") {
             let len = end - rest_start;
            if len == 0 {
                println!("Usage: decrypt <file>");
            } else {
                let filename = self.buffer[rest_start..end].iter().collect::<alloc::string::String>();
                let path_str = self.resolve_path(&filename);
                let vfs_lock = crate::vfs::VFS.lock();
                if let Some(fs) = vfs_lock.as_ref() {
                    match fs.resolve_path("/", &path_str) {
                        Ok(inode) => {
                             // Read current flags first
                             match inode.control(1, 0) {
                                 Ok(flags) => {
                                     // Clear Encrypted bit (1)
                                     match inode.control(2, flags & !1) {
                                         Ok(_) => println!("File '{}' decrypted.", filename),
                                         Err(e) => println!("Failed to decrypt: {}", e),
                                     }
                                 },
                                 Err(e) => println!("Failed to get flags: {}", e),
                             }
                        },
                        Err(e) => println!("decrypt: {}: {}", filename, e),
                    }
                } else {
                    println!("decrypt: VFS not mounted");
                }
            }
        } else if self.word_eq(word_start, word_end, "history") {
            self.print_history();
        } else if self.word_eq(word_start, word_end, "post") {
            if self.boot_info.is_null() || self.allocator.is_null() || self.slots.is_null() || self.frame_allocator.is_null() {
                println!("Cannot run POST: missing dependencies");
            } else {
                println!("Running POST (Power-On Self-Test)...");
                unsafe { tests::run_all(&*self.boot_info, &mut *self.allocator, &mut *self.slots, &mut *self.frame_allocator) };
            }
        } else if self.word_eq(word_start, word_end, "runhello") {
            let mut data_opt: Option<alloc::vec::Vec<u8>> = None;
            {
                let vfs_lock = crate::vfs::VFS.lock();
                if let Some(fs) = vfs_lock.as_ref() {
                    if let Ok(data) = fs.read_file("/bin/hello") {
                        data_opt = Some(data);
                    }
                }
            }
            
            // Prepare environment variables
            let env_vec: alloc::vec::Vec<alloc::string::String> = self.env_vars.iter()
                .map(|(k, v)| alloc::format!("{}={}", k, v))
                .collect();
            let env_slice: alloc::vec::Vec<&str> = env_vec.iter().map(|s| s.as_str()).collect();

            if let Some(data) = data_opt {
                self.spawn_process("hello", &data, &[], &env_slice);
            } else if let Some(data) = crate::filesystem::get_file("hello") {
                 self.spawn_process("hello", data, &[], &env_slice);
            } else {
                println!("Error: hello binary not found in /bin");
            }
        } else if self.word_eq(word_start, word_end, "ls") {
            let path_str = if rest_start < end {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                self.resolve_path(&s)
            } else {
                self.cwd.clone()
            };
            
            let fs_lock = crate::fs::DISK_FS.lock();
            if let Some(fs) = fs_lock.as_ref() {
                // Use resolve_path_ex to avoid following symlink if it's the last component
                match fs.resolve_path_ex(&self.cwd, &path_str, false) {
                    Ok(inode) => {
                        if let Ok(stat) = inode.metadata() {
                             if stat.file_type == crate::vfs::FileType::Directory {
                                 match inode.list() {
                                    Ok(entries) => {
                                        for (name, child) in entries {
                                            if let Ok(cstat) = child.metadata() {
                                                let type_char = match cstat.file_type {
                                                    crate::vfs::FileType::Directory => 'd',
                                                    crate::vfs::FileType::Symlink => 'l',
                                                    _ => '-',
                                                };
                                                let mode_str = Self::format_mode(cstat.mode);
                                                let time_str = Self::format_time(cstat.mtime);
                                                
                                                let mut name_display = name.clone();
                                                if cstat.file_type == crate::vfs::FileType::Symlink {
                                                    let mut buf = alloc::vec![0u8; cstat.size];
                                                    if let Ok(n) = child.read_at(0, &mut buf) {
                                                        if let Ok(target) = core::str::from_utf8(&buf[..n]) {
                                                                name_display = alloc::format!("{} -> {}", name, target);
                                                        }
                                                    }
                                                }
                                                
                                                println!("{}{} {:>2} {:>4} {:>4} {:>8} {} {}", type_char, mode_str, cstat.nlink, cstat.uid, cstat.gid, cstat.size, time_str, name_display);
                                            } else {
                                                println!("?rw-r--r--  1    0    0        0 1970-01-01 00:00:00 {}", name);
                                            }
                                        }
                                    },
                                    Err(e) => println!("ls: {}", e),
                                }
                             } else {
                                 let type_char = match stat.file_type {
                                     crate::vfs::FileType::Directory => 'd',
                                     crate::vfs::FileType::Symlink => 'l',
                                     _ => '-',
                                 };
                                 let mode_str = Self::format_mode(stat.mode);
                                 let time_str = Self::format_time(stat.mtime);
                                 
                                 let mut name_display = path_str.clone();
                                 if stat.file_type == crate::vfs::FileType::Symlink {
                                     let mut buf = alloc::vec![0u8; stat.size];
                                     if let Ok(n) = inode.read_at(0, &mut buf) {
                                         if let Ok(target) = core::str::from_utf8(&buf[..n]) {
                                              name_display = alloc::format!("{} -> {}", path_str, target);
                                         }
                                     }
                                 }
                                 
                                 println!("{}{} {:>2} {:>4} {:>4} {:>8} {} {}", type_char, mode_str, stat.nlink, stat.uid, stat.gid, stat.size, time_str, name_display);
                             }
                         } else {
                             println!("ls: cannot stat {}", path_str);
                         }
                    },
                    Err(e) => println!("ls: {}: {}", path_str, e),
                }
            } else {
                println!("ls: Filesystem not mounted");
            }
        } else if self.word_eq(word_start, word_end, "env") {
             for (k, v) in &self.env_vars {
                 println!("{}={}", k, v);
             }
        } else if self.word_eq(word_start, word_end, "export") {
             let len = end - rest_start;
             if len == 0 {
                 println!("Usage: export KEY=VALUE");
             } else {
                 let s = &self.buffer[rest_start..end];
                 let s = s.iter().collect::<alloc::string::String>();
                 if let Some(idx) = s.find('=') {
                     let key = &s[..idx];
                     let val = &s[idx+1..];
                     self.env_vars.insert(key.into(), val.into());
                 } else {
                     println!("Usage: export KEY=VALUE");
                 }
             }
        } else if self.word_eq(word_start, word_end, "unset") {
             let len = end - rest_start;
             if len == 0 {
                 println!("Usage: unset KEY");
             } else {
                 let s = &self.buffer[rest_start..end];
                 let key = s.iter().collect::<alloc::string::String>();
                 self.env_vars.remove(&key);
             }
        } else if self.word_eq(word_start, word_end, "cd") {
            let len = end - rest_start;
            if len == 0 {
                self.cwd = alloc::string::String::from("/");
            } else {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                let path_str = self.resolve_path(&s);
                
                let fs_lock = crate::fs::DISK_FS.lock();
                if let Some(fs) = fs_lock.as_ref() {
                    match crate::vfs::resolve_path(fs, &self.cwd, &path_str) {
                         Ok(inode) => {
                             if let Ok(stat) = inode.metadata() {
                                 if stat.file_type == crate::vfs::FileType::Directory {
                                     self.cwd = path_str;
                                     if self.cwd.len() > 1 && self.cwd.ends_with('/') {
                                         self.cwd.pop();
                                     }
                                 } else {
                                     println!("cd: {}: Not a directory", path_str);
                                 }
                             }
                         },
                         Err(e) => println!("cd: {}: {}", path_str, e),
                    }
                } else {
                    println!("cd: Filesystem not mounted");
                }
            }
        } else if self.word_eq(word_start, word_end, "mkdir") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: mkdir <dirname>");
            } else {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                let path_str = self.resolve_path(&s);
                
                let (parent_path, name) = if let Some(idx) = path_str.rfind('/') {
                    if idx == 0 { ("/", &path_str[1..]) }
                    else { (&path_str[..idx], &path_str[idx+1..]) }
                } else {
                    (self.cwd.as_str(), path_str.as_str())
                };
                
                if name.is_empty() {
                    println!("mkdir: Invalid name");
                } else {
                    let fs_lock = crate::fs::DISK_FS.lock();
                    if let Some(fs) = fs_lock.as_ref() {
                         match crate::vfs::resolve_path(fs, &self.cwd, parent_path) {
                             Ok(parent) => {
                                 match parent.create(name, crate::vfs::FileType::Directory) {
                                    Ok(_) => {
                                        println!("Created directory {}", path_str);
                                        fs.sync().ok();
                                    },
                                    Err(e) => println!("mkdir: {}", e),
                                }
                             },
                             Err(e) => println!("mkdir: parent {}: {}", parent_path, e),
                         }
                    } else {
                        println!("mkdir: Filesystem not mounted");
                    }
                }
            }
        } else if self.word_eq(word_start, word_end, "cat") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: cat <filename>");
            } else {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                let path_str = self.resolve_path(&s);
                
                let fs_lock = crate::fs::DISK_FS.lock();
                if let Some(fs) = fs_lock.as_ref() {
                    match crate::vfs::resolve_path(fs, &self.cwd, &path_str) {
                         Ok(inode) => {
                             if let Ok(stat) = inode.metadata() {
                                 if stat.file_type == crate::vfs::FileType::File {
                                     let mut buf = alloc::vec![0u8; stat.size];
                                     match inode.read_at(0, &mut buf) {
                                         Ok(_) => {
                                              if let Ok(s) = core::str::from_utf8(&buf) {
                                                  print!("{}", s);
                                                  if !s.ends_with('\n') { println!(); }
                                              } else {
                                                  println!("(Binary file, {} bytes)", stat.size);
                                              }
                                         },
                                         Err(e) => println!("cat: read error: {}", e),
                                     }
                                 } else {
                                     println!("cat: {}: Is a directory", path_str);
                                 }
                             } else {
                                 println!("cat: {}: cannot stat", path_str);
                             }
                         },
                         Err(e) => println!("cat: {}: {}", path_str, e),
                    }
                } else {
                    println!("cat: Filesystem not mounted");
                }
            }
        } else if self.word_eq(word_start, word_end, "rm") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: rm <path>");
            } else {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                let path_str = self.resolve_path(&s);
                
                let fs_lock = crate::fs::DISK_FS.lock();
                if let Some(fs) = fs_lock.as_ref() {
                    let (parent_path, name) = if let Some(idx) = path_str.rfind('/') {
                        if idx == 0 { ("/", &path_str[1..]) }
                        else { (&path_str[..idx], &path_str[idx+1..]) }
                    } else {
                        (self.cwd.as_str(), path_str.as_str())
                    };
                    
                    if name.is_empty() || name == "." || name == ".." {
                        println!("rm: invalid argument");
                    } else {
                        match crate::vfs::resolve_path(fs, &self.cwd, parent_path) {
                            Ok(parent) => {
                                match parent.remove(name) {
                                    Ok(_) => println!("Removed '{}'", path_str),
                                    Err(e) => println!("rm: cannot remove '{}': {}", path_str, e),
                                }
                            },
                            Err(e) => println!("rm: {}: {}", parent_path, e),
                        }
                    }
                } else {
                    println!("rm: Filesystem not mounted");
                }
            }
        } else if self.word_eq(word_start, word_end, "cp") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: cp <src> <dest>");
            } else {
                let mut space_idx = None;
                for i in rest_start..end {
                    if self.buffer[i] == ' ' {
                        space_idx = Some(i);
                        break;
                    }
                }

                if let Some(sp) = space_idx {
                     let src_s = &self.buffer[rest_start..sp];
                     let src_str = src_s.iter().collect::<alloc::string::String>();
                     
                     let mut dest_start = sp + 1;
                     while dest_start < end && self.buffer[dest_start] == ' ' {
                         dest_start += 1;
                     }
                     let dest_s = &self.buffer[dest_start..end];
                     let dest_str = dest_s.iter().collect::<alloc::string::String>();
                     
                     let src_path = self.resolve_path(&src_str);
                     let dest_path = self.resolve_path(&dest_str);
                     
                     let fs_lock = crate::fs::DISK_FS.lock();
                     if let Some(fs) = fs_lock.as_ref() {
                          match fs.read_file(&src_path) {
                              Ok(data) => {
                                  match fs.write_file(&dest_path, &data) {
                                      Ok(_) => println!("Copied '{}' to '{}'", src_path, dest_path),
                                      Err(e) => println!("cp: write error: {}", e),
                                  }
                              },
                              Err(e) => println!("cp: read error: {}", e),
                          }
                     } else {
                         println!("cp: Filesystem not mounted");
                     }
                } else {
                    println!("Usage: cp <src> <dest>");
                }
            }
        } else if self.word_eq(word_start, word_end, "encrypt") {
            let path_str = if rest_start < end {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                self.resolve_path(&s)
            } else {
                println!("Usage: encrypt <file>");
                return;
            };
            
            let fs_lock = crate::fs::DISK_FS.lock();
            if let Some(fs) = fs_lock.as_ref() {
                match fs.resolve_path_ex(&self.cwd, &path_str, true) {
                    Ok(inode) => {
                         if let Ok(flags) = inode.control(1, 0) {
                             if (flags & 1) != 0 {
                                 println!("File '{}' is already encrypted.", path_str);
                             } else {
                                 match inode.control(2, flags | 1) {
                                     Ok(_) => println!("File '{}' encrypted.", path_str),
                                     Err(e) => println!("Failed to encrypt: {}", e),
                                 }
                             }
                         } else {
                             println!("Failed to get file flags.");
                         }
                    },
                    Err(e) => println!("encrypt: {}: {}", path_str, e),
                }
            }
        } else if self.word_eq(word_start, word_end, "decrypt") {
            let path_str = if rest_start < end {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                self.resolve_path(&s)
            } else {
                println!("Usage: decrypt <file>");
                return;
            };
            
            let fs_lock = crate::fs::DISK_FS.lock();
            if let Some(fs) = fs_lock.as_ref() {
                match fs.resolve_path_ex(&self.cwd, &path_str, true) {
                    Ok(inode) => {
                         if let Ok(flags) = inode.control(1, 0) {
                             if (flags & 1) == 0 {
                                 println!("File '{}' is not encrypted.", path_str);
                             } else {
                                 match inode.control(2, flags & !1) {
                                     Ok(_) => println!("File '{}' decrypted.", path_str),
                                     Err(e) => println!("Failed to decrypt: {}", e),
                                 }
                             }
                         } else {
                             println!("Failed to get file flags.");
                         }
                    },
                    Err(e) => println!("decrypt: {}: {}", path_str, e),
                }
            }
        } else if self.word_eq(word_start, word_end, "ln") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: ln [-s] <target> <link_name>");
            } else {
                let mut args_start = rest_start;
                let mut is_symlink = false;
                
                // Check for -s
                if end - rest_start >= 3 && self.buffer[rest_start] == '-' && self.buffer[rest_start+1] == 's' && self.buffer[rest_start+2] == ' ' {
                    is_symlink = true;
                    args_start += 3;
                    while args_start < end && self.buffer[args_start] == ' ' {
                        args_start += 1;
                    }
                }

                let mut space_idx = None;
                for i in args_start..end {
                    if self.buffer[i] == ' ' {
                        space_idx = Some(i);
                        break;
                    }
                }

                if let Some(sp) = space_idx {
                     let target_s = &self.buffer[args_start..sp];
                     let target_str = target_s.iter().collect::<alloc::string::String>();
                     
                     let mut link_start = sp + 1;
                     while link_start < end && self.buffer[link_start] == ' ' {
                         link_start += 1;
                     }
                     let link_s = &self.buffer[link_start..end];
                     let link_str = link_s.iter().collect::<alloc::string::String>();
                     
                     let link_path = self.resolve_path(&link_str);
                     
                     let fs_lock = crate::fs::DISK_FS.lock();
                     if let Some(fs) = fs_lock.as_ref() {
                          if is_symlink {
                               // Symlink creation
                               let (parent_path, name) = if let Some(idx) = link_path.rfind('/') {
                                    if idx == 0 { ("/", &link_path[1..]) }
                                    else { (&link_path[..idx], &link_path[idx+1..]) }
                               } else {
                                   ("/", link_path.as_str())
                               };
                               
                               if name.is_empty() {
                                   println!("ln: Invalid link name");
                               } else {
                                   match crate::vfs::resolve_path(fs, &self.cwd, parent_path) {
                                        Ok(parent) => {
                                            match parent.create(name, crate::vfs::FileType::Symlink) {
                                                Ok(inode) => {
                                                    match inode.write_at(0, target_str.as_bytes()) {
                                                        Ok(_) => println!("Created symbolic link '{}' -> '{}'", link_path, target_str),
                                                        Err(e) => println!("ln: write failed: {}", e),
                                                    }
                                                },
                                                Err(e) => println!("ln: create failed: {}", e),
                                            }
                                        },
                                        Err(e) => println!("ln: parent {}: {}", parent_path, e),
                                   }
                               }
                          } else {
                              // Hard link creation
                              let target_path = self.resolve_path(&target_str);
                              match crate::vfs::resolve_path(fs, &self.cwd, &target_path) {
                                  Ok(target_inode) => {
                                       let (parent_path, name) = if let Some(idx) = link_path.rfind('/') {
                                            if idx == 0 { ("/", &link_path[1..]) }
                                            else { (&link_path[..idx], &link_path[idx+1..]) }
                                       } else {
                                           ("/", link_path.as_str())
                                       };
                                       
                                       if name.is_empty() {
                                           println!("ln: Invalid link name");
                                       } else {
                                           match crate::vfs::resolve_path(fs, &self.cwd, parent_path) {
                                                Ok(parent) => {
                                                    match parent.link(name, target_inode.as_ref()) {
                                                        Ok(_) => println!("Created hard link '{}' => '{}'", link_path, target_path),
                                                        Err(e) => println!("ln: failed to link: {}", e),
                                                    }
                                                },
                                                Err(e) => println!("ln: parent {}: {}", parent_path, e),
                                           }
                                       }
                                  },
                                  Err(e) => println!("ln: target {}: {}", target_path, e),
                              }
                          }
                     } else {
                         println!("ln: Filesystem not mounted");
                     }
                } else {
                    println!("Usage: ln [-s] <target> <link_name>");
                }
            }
        } else if self.word_eq(word_start, word_end, "chmod") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: chmod <mode> <file>");
            } else {
                let mut space_idx = None;
                for i in rest_start..end {
                    if self.buffer[i] == ' ' {
                        space_idx = Some(i);
                        break;
                    }
                }
                
                if let Some(sp) = space_idx {
                     let mode_s = &self.buffer[rest_start..sp];
                     let mode_str = mode_s.iter().collect::<alloc::string::String>();
                     
                     let mut file_start = sp + 1;
                     while file_start < end && self.buffer[file_start] == ' ' {
                         file_start += 1;
                     }
                     let file_s = &self.buffer[file_start..end];
                     let file_str = file_s.iter().collect::<alloc::string::String>();
                     
                     if let Ok(mode) = u16::from_str_radix(&mode_str, 8) {
                         let path_str = self.resolve_path(&file_str);
                         let fs_lock = crate::fs::DISK_FS.lock();
                         if let Some(fs) = fs_lock.as_ref() {
                              match crate::vfs::resolve_path(fs, &self.cwd, &path_str) {
                                  Ok(inode) => {
                                      match inode.control(4, mode as u64) {
                                          Ok(_) => println!("Changed mode of '{}' to {:o}", path_str, mode),
                                          Err(e) => println!("chmod: {}", e),
                                      }
                                  },
                                  Err(e) => println!("chmod: {}: {}", path_str, e),
                              }
                         } else {
                             println!("chmod: Filesystem not mounted");
                         }
                     } else {
                         println!("chmod: Invalid mode (octal required)");
                     }
                } else {
                    println!("Usage: chmod <mode> <file>");
                }
            }
        } else if self.word_eq(word_start, word_end, "chown") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: chown <uid:gid> <file>");
            } else {
                let mut space_idx = None;
                for i in rest_start..end {
                    if self.buffer[i] == ' ' {
                        space_idx = Some(i);
                        break;
                    }
                }
                
                if let Some(sp) = space_idx {
                     let owner_s = &self.buffer[rest_start..sp];
                     let owner_str = owner_s.iter().collect::<alloc::string::String>();
                     
                     let mut file_start = sp + 1;
                     while file_start < end && self.buffer[file_start] == ' ' {
                         file_start += 1;
                     }
                     let file_s = &self.buffer[file_start..end];
                     let file_str = file_s.iter().collect::<alloc::string::String>();
                     
                     let parts: alloc::vec::Vec<&str> = owner_str.split(':').collect();
                     if parts.len() == 2 {
                         if let (Ok(uid), Ok(gid)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                             let path_str = self.resolve_path(&file_str);
                             let fs_lock = crate::fs::DISK_FS.lock();
                             if let Some(fs) = fs_lock.as_ref() {
                                  match crate::vfs::resolve_path(fs, &self.cwd, &path_str) {
                                      Ok(inode) => {
                                          let mut success = true;
                                          if let Err(e) = inode.control(5, uid as u64) {
                                              println!("chown: failed to set uid: {}", e);
                                              success = false;
                                          }
                                          if success {
                                              if let Err(e) = inode.control(6, gid as u64) {
                                                  println!("chown: failed to set gid: {}", e);
                                              } else {
                                                  println!("Changed ownership of '{}' to {}:{}", path_str, uid, gid);
                                              }
                                          }
                                      },
                                      Err(e) => println!("chown: {}: {}", path_str, e),
                                  }
                             } else {
                                 println!("chown: Filesystem not mounted");
                             }
                         } else {
                             println!("chown: Invalid uid/gid");
                         }
                     } else {
                         println!("chown: Invalid format (uid:gid required)");
                     }
                } else {
                    println!("Usage: chown <uid:gid> <file>");
                }
            }
        } else if self.word_eq(word_start, word_end, "mv") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: mv <src> <dest>");
            } else {
                let mut space_idx = None;
                for i in rest_start..end {
                    if self.buffer[i] == ' ' {
                        space_idx = Some(i);
                        break;
                    }
                }

                if let Some(sp) = space_idx {
                     let src_s = &self.buffer[rest_start..sp];
                     let src_str = src_s.iter().collect::<alloc::string::String>();
                     
                     let mut dest_start = sp + 1;
                     while dest_start < end && self.buffer[dest_start] == ' ' {
                         dest_start += 1;
                     }
                     let dest_s = &self.buffer[dest_start..end];
                     let dest_str = dest_s.iter().collect::<alloc::string::String>();
                     
                     let src_path = self.resolve_path(&src_str);
                     let mut dest_path = self.resolve_path(&dest_str);
                     
                     let fs_lock = crate::fs::DISK_FS.lock();
                     if let Some(fs) = fs_lock.as_ref() {
                          // Check if dest is a directory
                          let mut dest_is_dir = false;
                          if let Ok(inode) = crate::vfs::resolve_path(fs, &self.cwd, &dest_path) {
                               if let Ok(stat) = inode.metadata() {
                                   if stat.file_type == crate::vfs::FileType::Directory {
                                       dest_is_dir = true;
                                   }
                               }
                          }

                          if dest_is_dir {
                               let src_name = if let Some(idx) = src_path.rfind('/') {
                                   &src_path[idx+1..]
                               } else {
                                   &src_path
                               };
                               if !dest_path.ends_with('/') { dest_path.push('/'); }
                               dest_path.push_str(src_name);
                          }

                          // Split paths
                          let (src_parent_path, src_name) = if let Some(idx) = src_path.rfind('/') {
                               if idx == 0 { ("/", &src_path[1..]) }
                               else { (&src_path[..idx], &src_path[idx+1..]) }
                          } else {
                               (self.cwd.as_str(), src_path.as_str())
                          };

                          let (dest_parent_path, dest_name) = if let Some(idx) = dest_path.rfind('/') {
                               if idx == 0 { ("/", &dest_path[1..]) }
                               else { (&dest_path[..idx], &dest_path[idx+1..]) }
                          } else {
                               (self.cwd.as_str(), dest_path.as_str())
                          };

                          // Perform rename
                          match crate::vfs::resolve_path(fs, &self.cwd, src_parent_path) {
                               Ok(src_parent) => {
                                   match crate::vfs::resolve_path(fs, &self.cwd, dest_parent_path) {
                                       Ok(dest_parent) => {
                                           match src_parent.rename(src_name, &dest_parent, dest_name) {
                                               Ok(_) => println!("Renamed '{}' to '{}'", src_path, dest_path),
                                               Err(e) => println!("mv: {}", e),
                                           }
                                       },
                                       Err(e) => println!("mv: dest parent {}: {}", dest_parent_path, e),
                                   }
                               },
                               Err(e) => println!("mv: src parent {}: {}", src_parent_path, e),
                          }
                     } else {
                         println!("mv: Filesystem not mounted");
                     }
                } else {
                    println!("Usage: mv <src> <dest>");
                }
            }
        } else if self.word_eq(word_start, word_end, "touch") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: touch <filename>");
            } else {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                let path_str = self.resolve_path(&s);
                
                let fs_lock = crate::fs::DISK_FS.lock();
                if let Some(fs) = fs_lock.as_ref() {
                    let (parent_path, name) = if let Some(idx) = path_str.rfind('/') {
                        if idx == 0 { ("/", &path_str[1..]) }
                        else { (&path_str[..idx], &path_str[idx+1..]) }
                    } else {
                        (self.cwd.as_str(), path_str.as_str())
                    };
                    
                    if name.is_empty() {
                         println!("touch: Invalid name");
                    } else {
                        match crate::vfs::resolve_path(fs, &self.cwd, parent_path) {
                             Ok(parent) => {
                                 if let Ok(_) = parent.lookup(name) {
                                      // Exists, do nothing
                                 } else {
                                      match parent.create(name, crate::vfs::FileType::File) {
                                          Ok(_) => println!("Created '{}'", path_str),
                                          Err(e) => println!("touch: {}", e),
                                      }
                                 }
                             },
                             Err(e) => println!("touch: {}: {}", parent_path, e),
                        }
                    }
                } else {
                     println!("touch: Filesystem not mounted");
                }
            }
        } else if self.word_eq(word_start, word_end, "pwd") {
            println!("{}", self.cwd);
        } else if self.word_eq(word_start, word_end, "truncate") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: truncate <file> <size>");
            } else {
                let s = &self.buffer[rest_start..end];
                let s_str = s.iter().collect::<alloc::string::String>();
                let parts: alloc::vec::Vec<&str> = s_str.split_whitespace().collect();
                
                if parts.len() < 2 {
                    println!("Usage: truncate <file> <size>");
                } else {
                    let filename = parts[0];
                    let size_str = parts[1];
                    let size = size_str.parse::<u64>().unwrap_or(0);
                    
                    let path_str = self.resolve_path(filename);
                    
                    let fs_lock = crate::fs::DISK_FS.lock();
                    if let Some(fs) = fs_lock.as_ref() {
                        match crate::vfs::resolve_path(fs, "/", &path_str) {
                        Ok(inode) => {
                            match inode.control(3, size) {
                                Ok(_) => println!("Truncated '{}' to {} bytes.", path_str, size),
                                Err(e) => println!("truncate: {}", e),
                            }
                        },
                        Err(_) => {
                             match fs.create_file(&path_str) {
                                 Ok(inode) => {
                                     match inode.control(3, size) {
                                         Ok(_) => println!("Truncated '{}' to {} bytes.", path_str, size),
                                         Err(e) => println!("truncate: {}", e),
                                     }
                                 },
                                 Err(e) => println!("truncate: {}: {}", path_str, e),
                             }
                        }
                    }
                    } else {
                        println!("truncate: Filesystem not mounted");
                    }
                }
            }
        } else if self.word_eq(word_start, word_end, "writetest") {
            let len = end - rest_start;
            let (filename, size_kb) = if len == 0 {
                ("test.dat".to_string(), 100)
            } else {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                let parts: alloc::vec::Vec<&str> = s.split_whitespace().collect();
                if parts.len() >= 2 {
                    (parts[0].to_string(), parts[1].parse::<usize>().unwrap_or(100))
                } else if parts.len() == 1 {
                    (parts[0].to_string(), 100)
                } else {
                    ("test.dat".to_string(), 100)
                }
            };
            
            let path_str = self.resolve_path(&filename);
            println!("Writing {} KB to {}", size_kb, path_str);
            
            let mut data = alloc::vec::Vec::with_capacity(size_kb * 1024);
            for i in 0..size_kb * 1024 {
                data.push((i % 256) as u8);
            }
            
            let fs_lock = crate::fs::DISK_FS.lock();
            if let Some(fs) = fs_lock.as_ref() {
                 match fs.write_file(&path_str, &data) {
                     Ok(_) => println!("Write success"),
                     Err(e) => println!("Write failed: {}", e),
                 }
            } else {
                println!("writetest: Filesystem not mounted");
            }
        } else if self.word_eq(word_start, word_end, "echo") {
            let mut redirect_idx = None;
            for i in rest_start..end {
                if self.buffer[i] == '>' {
                    redirect_idx = Some(i);
                    break;
                }
            }

            if let Some(idx) = redirect_idx {
                 let content_end = idx;
                 let mut fn_start = idx + 1;
                 while fn_start < end && self.buffer[fn_start] == ' ' { fn_start += 1; }
                 
                 let s = &self.buffer[fn_start..end];
                 let s = s.iter().collect::<alloc::string::String>();
                 let path_str = self.resolve_path(&s);
                 
                 let content_s = &self.buffer[rest_start..content_end];
                 let mut content_vec = alloc::vec::Vec::new();
                 for c in content_s {
                      let mut b = [0; 4];
                      let s = c.encode_utf8(&mut b);
                      content_vec.extend_from_slice(s.as_bytes());
                 }
                 if !content_vec.is_empty() && content_vec[content_vec.len()-1] == b' ' {
                     content_vec.pop();
                 }

                 let fs_lock = crate::fs::DISK_FS.lock();
                 if let Some(fs) = fs_lock.as_ref() {
                      match fs.write_file(&path_str, &content_vec) {
                          Ok(_) => println!("Written to {}", path_str),
                          Err(e) => println!("echo: write error: {}", e),
                      }
                 } else {
                      println!("echo: Filesystem not mounted");
                 }
            } else {
                if rest_start >= end {
                    println!();
                } else {
                    for i in rest_start..end {
                        print!("{}", self.buffer[i]);
                    }
                    println!();
                }
            }
        } else {
             print!("Unknown command: ");
            for i in word_start..word_end {
                print!("{}", self.buffer[i]);
            }
            println!();
        }
    }

    fn spawn_process(&mut self, name: &str, elf_data: &[u8], args: &[&str], env: &[&str]) {
        if self.boot_info.is_null() || self.allocator.is_null() || self.slots.is_null() || self.frame_allocator.is_null() {
            println!("spawn_process: unavailable");
            return;
        }

        use crate::process::{Process, get_process_manager};
        use sel4_sys::*;

        let bi = unsafe { &*self.boot_info };
        let alloc = unsafe { &mut *self.allocator };
        let slots = unsafe { &mut *self.slots };
        let frame_alloc = unsafe { &mut *self.frame_allocator };

        // 1. Allocate PID
        let mut pm = get_process_manager();
        let pid = match pm.allocate_pid() {
            Ok(p) => p,
            Err(e) => {
                    println!("[RUN] Failed to allocate PID: {:?}", e);
                    return;
            }
        };
        
        let badge = 100 + pid;

        // 2. Mint Badged Endpoint
        let badged_ep_slot = match slots.alloc() {
            Ok(s) => s,
            Err(_) => {
                println!("[RUN] Failed to allocate slot for badged EP");
                return;
            }
        };

        let root_cnode_cap = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
        let root_cnode = libnova::cap::CNode::new(root_cnode_cap, seL4_WordBits as u8);
        
        if let Err(e) = root_cnode.mint(
            badged_ep_slot,
            &root_cnode,
            self.syscall_ep_cap,
            cap_rights_new(false, true, true, true),
            badge as seL4_Word
        ) {
            println!("[RUN] Failed to mint badged endpoint: {:?}", e);
            return;
        }

        println!("[RUN] Spawning process '{}' (PID {})...", name, pid);

        // 3. Spawn Process
        match Process::spawn(alloc, slots, frame_alloc, bi, name, elf_data, args, env, 100, badged_ep_slot, 32, 0, 0) {
            Ok(process) => {
                    // 4. Add to Manager
                    if let Err(e) = pm.add_process(process) {
                        println!("[RUN] Failed to add process to manager: {:?}", e);
                    } else {
                        println!("[RUN] Process spawned successfully (PID {}).", pid);
                    }
            }
            Err(e) => println!("[RUN] Spawn failed: {:?}", e),
        }
    }

    fn print_history(&self) {
        if self.history_count == 0 {
            println!("history: empty");
            return;
        }
        let n = if self.history_count > 10 {
            10
        } else {
            self.history_count
        };
        for i in 0..n {
            let pos = self.history_count - 1 - i;
            let (idx, len) = self.history_pos_to_ring(pos);
            print!("{}  ", pos);
            for j in 0..len {
                print!("{}", self.history[idx][j]);
            }
            println!();
        }
    }
    
    fn history_push(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }
        let mut len = end - start;
        if len > MAX_CMD_LEN {
            len = MAX_CMD_LEN;
        }

        if self.history_count != 0 {
            let prev_pos = self.history_count - 1;
            let (prev_idx, prev_len) = self.history_pos_to_ring(prev_pos);
            if prev_len == len {
                let mut same = true;
                for i in 0..len {
                    if self.history[prev_idx][i] != self.buffer[start + i] {
                        same = false;
                        break;
                    }
                }
                if same {
                    return;
                }
            }
        }

        let idx = self.history_head;
        for i in 0..len {
            self.history[idx][i] = self.buffer[start + i];
        }
        for i in len..MAX_CMD_LEN {
            self.history[idx][i] = '\0';
        }
        self.history_lens[idx] = len;
        self.history_head = (self.history_head + 1) % HISTORY_LEN;
        if self.history_count < HISTORY_LEN {
            self.history_count += 1;
        }
    }

    fn trim_range(&self) -> Option<(usize, usize)> {
        let mut start = 0;
        while start < self.len {
            let c = self.buffer[start];
            if c != ' ' && c != '\t' {
                break;
            }
            start += 1;
        }
        if start >= self.len {
            return None;
        }
        let mut end = self.len;
        while end > start {
            let c = self.buffer[end - 1];
            if c != ' ' && c != '\t' {
                break;
            }
            end -= 1;
        }
        if end <= start {
            None
        } else {
            Some((start, end))
        }
    }

    fn split_word(&self, start: usize, end: usize) -> (usize, usize, usize) {
        let mut word_end = start;
        while word_end < end {
            let c = self.buffer[word_end];
            if c == ' ' || c == '\t' {
                break;
            }
            word_end += 1;
        }
        let mut rest_start = word_end;
        while rest_start < end {
            let c = self.buffer[rest_start];
            if c != ' ' && c != '\t' {
                break;
            }
            rest_start += 1;
        }
        (start, word_end, rest_start)
    }

    fn word_eq(&self, start: usize, end: usize, s: &str) -> bool {
        if end - start != s.len() {
            return false;
        }
        for (i, c) in s.chars().enumerate() {
            if self.buffer[start + i] != c {
                return false;
            }
        }
        true
    }
}
