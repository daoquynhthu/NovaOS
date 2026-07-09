use crate::drivers::keyboard::Key;
use crate::memory::{FrameAllocator, SlotAllocator, UntypedAllocator};
use crate::tests;
use alloc::string::ToString;
use alloc::vec;
use libnova::cap::cap_rights_new;
#[allow(unused_imports)]
use libnova::fs_ipc::{
    chmod_direct as fs_chmod_direct, chown_direct as fs_chown_direct,
    close_direct as fs_close_direct, decrypt_direct as fs_decrypt_direct,
    encrypt_direct as fs_encrypt_direct, link_direct as fs_link_direct,
    list_direct as fs_list_direct, mkdir_direct as fs_mkdir_direct,
    open_direct as fs_open_direct, read_direct as fs_read_direct,
    rename_direct as fs_rename_direct, stat_direct as fs_stat_direct,
    symlink_direct as fs_symlink_direct, sync_direct as fs_sync_direct,
    truncate_direct as fs_truncate_direct, unlink_direct as fs_unlink_direct,
    write_direct as fs_write_direct, writetest_direct as fs_writetest_direct,
};
use sel4_sys::seL4_BootInfo;

const MAX_CMD_LEN: usize = 64;
const HISTORY_LEN: usize = 16;

const COMMANDS: &[&str] = &[
    "help",
    "clear",
    "echo",
    "cat",
    "whoami",
    "status",
    "bootinfo",
    "alloc",
    "meminfo",
    "ps",
    "services",
    "svc",
    "ls",
    "kill",
    "exec",
    "history",
    "post",
    "runhello",
    "cd",
    "mkdir",
    "rm",
    "cp",
    "mv",
    "touch",
    "writetest",
    "pwd",
    "fsping",
    "renice",
    "pci",
    "date",
    "disk_read",
    "disk_write",
    "mkfs",
    "mount",
    "sync",
    "write",
    "encrypt",
    "decrypt",
    "ln",
    "chmod",
    "chown",
    "env",
    "export",
    "unset",
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
    pending_prompt_pid: Option<usize>,
    pending_cd_path: Option<alloc::string::String>,
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
            pending_prompt_pid: None,
            pending_cd_path: None,
        }
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

    fn prompt_deferred(&self) -> bool {
        self.pending_prompt_pid.is_some()
    }

    pub fn on_process_exit(&mut self, pid: usize, status: isize) -> bool {
        if self.pending_prompt_pid == Some(pid) {
            self.pending_prompt_pid = None;
            if let Some(path) = self.pending_cd_path.take() {
                if status == 0 {
                    self.cwd = path;
                    if self.cwd.len() > 1 && self.cwd.ends_with('/') {
                        self.cwd.pop();
                    }
                    println!("[SHELL] cd ok {}", self.cwd);
                } else {
                    println!("[SHELL] cd failed {} (status {})", path, status);
                }
            }
            self.print_prompt();
            true
        } else {
            false
        }
    }

    pub fn on_key(&mut self, k: Key) {
        match k {
            Key::Enter => {
                println!();
                self.history_view = None;
                self.draft_valid = false;
                self.execute_command();
                self.clear_line();
                if !self.prompt_deferred() {
                    self.print_prompt();
                }
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
            Key::F2
            | Key::F3
            | Key::F4
            | Key::F5
            | Key::F6
            | Key::F7
            | Key::F8
            | Key::F9
            | Key::F10
            | Key::F11
            | Key::F12 => {}
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
                if let Some(files) = novafs_core::VFS
                    .lock()
                    .as_ref()
                    .and_then(|fs| fs.list_dir("/bin").ok())
                {
                    for file in files {
                        if self.word_starts_with_str(word_start, &file) {
                            matches.push(file);
                        }
                    }
                }
            } else if self.command_is("ls")
                || self.command_is("cat")
                || self.command_is("cd")
                || self.command_is("rm")
                || self.command_is("touch")
            {
                if let Some(files) = novafs_core::VFS
                    .lock()
                    .as_ref()
                    .and_then(|fs| fs.list_dir(&self.cwd).ok())
                {
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
            if !s.ends_with('/') {
                s.push('/');
            }
            s.push_str(path);
            s
        };

        let mut components = alloc::vec::Vec::new();
        for part in full_path.split('/') {
            if part.is_empty() || part == "." {
                continue;
            }
            if part == ".." {
                components.pop();
            } else {
                components.push(part);
            }
        }

        let mut res = alloc::string::String::from("/");
        for (i, part) in components.iter().enumerate() {
            if i > 0 {
                res.push('/');
            }
            res.push_str(part);
        }
        res
    }

    fn fs_endpoint(&self) -> Option<sel4_sys::seL4_CPtr> {
        crate::services::lookup_latest_ready("fs").map(|(_, ep, _)| ep)
    }

    fn read_file_via_fs(&self, path_str: &str) -> Option<alloc::vec::Vec<u8>> {
        if let Some(fs_ep) = self.fs_endpoint() {
            let fd = fs_open_direct(fs_ep, path_str, 0);
            if fd >= 0 {
                let mut data = alloc::vec::Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = fs_read_direct(fs_ep, fd as usize, &mut buf);
                    if n <= 0 {
                        break;
                    }
                    data.extend_from_slice(&buf[..n as usize]);
                }
                fs_close_direct(fs_ep, fd as usize);
                return Some(data);
            }
        }
        None
    }

    fn load_hello_binary(&self) -> Option<alloc::vec::Vec<u8>> {
        if let Some(data) = self.read_file_via_fs("/bin/hello") {
            return Some(data);
        }
        {
            let vfs_lock = novafs_core::VFS.lock();
            if let Some(fs) = vfs_lock.as_ref() {
                if let Ok(data) = fs.read_file("/bin/hello") {
                    return Some(data);
                }
            }
        }

        crate::filesystem::get_file("hello").map(|data| data.to_vec())
    }

    fn build_child_env(&self, include_fs_service: bool) -> alloc::vec::Vec<alloc::string::String> {
        let mut env_vec: alloc::vec::Vec<alloc::string::String> = self
            .env_vars
            .iter()
            .map(|(k, v)| alloc::format!("{}={}", k, v))
            .collect();
        if include_fs_service {
            if let Some((_, fs_ep, _)) = crate::services::lookup_latest_ready("fs") {
                env_vec.push(alloc::format!("NOVA_FS_SERVICE_EP={}", fs_ep));
            }
        }
        env_vec
    }

    fn spawn_fs_helper_args(&mut self, args: &[&str]) -> bool {
        let Some(data) = self.load_hello_binary() else {
            return false;
        };
        let env_vec = self.build_child_env(true);
        if !env_vec
            .iter()
            .any(|entry| entry.starts_with("NOVA_FS_SERVICE_EP="))
        {
            return false;
        }
        let env_slice: alloc::vec::Vec<&str> = env_vec.iter().map(|s| s.as_str()).collect();
        if let Some(pid) = self.spawn_process("hello", &data, args, &env_slice) {
            self.pending_prompt_pid = Some(pid);
            true
        } else {
            false
        }
    }

    fn spawn_fs_helper(&mut self, mode: &str, path: &str) -> bool {
        let args = [mode, path];
        self.spawn_fs_helper_args(&args)
    }

    fn mark_fs_service_dirty(&self) {
        crate::services::bump_fs_view_epoch();
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
            println!("  writetest - Write a large test file");
            println!("  pwd       - Print working directory");
            println!("  whoami    - Show user info");
            println!("  status    - Show system status");
            println!("  bootinfo  - Show seL4 BootInfo summary");
            println!("  alloc     - Show allocator summary");
            println!("  meminfo   - Show memory usage summary");
            println!("  ps        - List tracked processes");
            println!("  services  - List registered kernel services");
            println!("  svc       - Resolve service (svc <name>)");
            println!("  fsping    - Ping fs service health endpoint");
            println!("  ls        - List available files");
            println!("  kill      - Kill a process by PID");
            println!("  exec      - Execute a program (e.g. exec hello)");
            println!("  history   - Show recent commands");
            println!("  post      - Run POST tests again");
            println!("  runhello  - Run minimal user-mode program [args...]");
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
                    let val = &s_str[idx + 1..];
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
                while i < end && self.buffer[i] == ' ' {
                    i += 1;
                }

                let mut lba = 0;
                while i < end && self.buffer[i].is_ascii_digit() {
                    lba = lba * 10 + (self.buffer[i] as usize - '0' as usize);
                    i += 1;
                }

                while i < end && self.buffer[i] == ' ' {
                    i += 1;
                }

                let mut sectors = 0;
                while i < end && self.buffer[i].is_ascii_digit() {
                    sectors = sectors * 10 + (self.buffer[i] as usize - '0' as usize);
                    i += 1;
                }

                if sectors == 0 {
                    sectors = 1;
                }

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
                    }
                    Err(e) => println!("Disk Read Error: {}", e),
                }
            }
        } else if self.word_eq(word_start, word_end, "disk_write") {
            let args_len = end - rest_start;
            if args_len == 0 {
                println!("Usage: disk_write <lba> <data_string>");
            } else {
                let mut i = rest_start;
                while i < end && self.buffer[i] == ' ' {
                    i += 1;
                }

                let mut lba = 0;
                while i < end && self.buffer[i].is_ascii_digit() {
                    lba = lba * 10 + (self.buffer[i] as usize - '0' as usize);
                    i += 1;
                }

                while i < end && self.buffer[i] == ' ' {
                    i += 1;
                }

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
                while i < end && self.buffer[i] == ' ' {
                    i += 1;
                }
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
                    let fs = novafs_core::novafs::NovaFS::format(drv, 0, total_blocks as u32);
                    *crate::fs::DISK_FS.lock() = Some(alloc::sync::Arc::new(fs));
                    println!("Format successful! Mounted as root.");
                }
            }
        } else if self.word_eq(word_start, word_end, "mount") {
            println!("Mounting NovaFS...");
            let drv = alloc::sync::Arc::new(crate::drivers::ata::AtaDriver::new(0x1F0));
            match novafs_core::novafs::NovaFS::new(drv, 0) {
                Ok(fs) => {
                    *crate::fs::DISK_FS.lock() = Some(alloc::sync::Arc::new(fs));
                    println!("Mount successful.");
                }
                Err(e) => {
                    println!("Mount failed: {}", e);
                }
            }
        } else if self.word_eq(word_start, word_end, "sync") {
            if let Some(fs_ep) = self.fs_endpoint() {
                if fs_sync_direct(fs_ep) >= 0 {
                    println!("[FS] Filesystem synced.");
                    return;
                }
            }
            if self.spawn_fs_helper_args(&["fs_sync"]) {
                return;
            }
            println!("sync: filesystem not available");
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
                println!(
                    "[INFO] Untyped Slots: {} - {}",
                    bi.untyped.start, bi.untyped.end
                );
                println!(
                    "[INFO] Untyped Memory: {} slots",
                    bi.untyped.end - bi.untyped.start
                );
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
                let frame_alloc = unsafe { &*self.frame_allocator };

                let (total_slots, used_slots, free_slots) = slots.stats();
                let (total_untyped, ram_untyped, used_bytes, total_bytes, last_used) =
                    alloc.stats(bi);
                let free_ram = alloc.free_ram_bytes(bi);
                let fragmented_tail = alloc.fragmentation_bytes(bi);
                let (oom_events, last_oom_bits) = alloc.oom_stats();

                println!(
                    "[MEM] CSpace Slots: total={}, used={}, free={}",
                    total_slots, used_slots, free_slots
                );
                println!(
                    "[MEM] Untyped Caps: total={}, ram={}",
                    total_untyped, ram_untyped
                );
                println!(
                    "[MEM] RAM Untyped Usage: used={} bytes, total={} bytes",
                    used_bytes, total_bytes
                );
                println!("[MEM] RAM Untyped Free: {} bytes", free_ram);
                println!("[MEM] Fragmented Tail (<4K): {} bytes", fragmented_tail);
                println!(
                    "[MEM] OOM Events: {}, LastOOMSizeBits={}",
                    oom_events, last_oom_bits
                );
                println!(
                    "[MEM] Frame Cache: {} recycled frames",
                    frame_alloc.free_count()
                );
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
                    print!(
                        "{:<12} {:<16} {:<10x} {:<6} {}",
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
        } else if self.word_eq(word_start, word_end, "services") {
            let entries = crate::services::list();
            if entries.is_empty() {
                println!("No services registered.");
            } else {
                println!("Name                 Endpoint   State");
                println!("------------------------------------------");
                for (name, endpoint, state) in entries {
                    let state_str = match state {
                        crate::services::ServiceState::Bootstrapping => "bootstrapping",
                        crate::services::ServiceState::Ready => "ready",
                    };
                    println!("{:<20} {:<10} {}", name, endpoint, state_str);
                }
            }
        } else if self.word_eq(word_start, word_end, "svc") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: svc <name>");
            } else {
                let query = self.buffer[rest_start..end]
                    .iter()
                    .collect::<alloc::string::String>();

                if let Some(entry) = crate::services::lookup_entry(&query) {
                    let state_str = match entry.state {
                        crate::services::ServiceState::Bootstrapping => "bootstrapping",
                        crate::services::ServiceState::Ready => "ready",
                    };
                    println!(
                        "service {} => {} (endpoint {}, state {})",
                        query, query, entry.endpoint, state_str
                    );
                } else if let Some((resolved_name, entry, _version)) =
                    crate::services::lookup_latest_entry(&query)
                {
                    let state_str = match entry.state {
                        crate::services::ServiceState::Bootstrapping => "bootstrapping",
                        crate::services::ServiceState::Ready => "ready",
                    };
                    println!(
                        "service {} => {} (endpoint {}, state {})",
                        query, resolved_name, entry.endpoint, state_str
                    );
                } else {
                    println!("service {} => <not found>", query);
                }
            }
        } else if self.word_eq(word_start, word_end, "fsping") {
            match crate::services::ping("fs") {
                Ok((status, proto, op_pair, rw_pair)) => {
                    if status == libnova::fs_ipc::FS_STATUS_READY {
                        let open_count = (op_pair >> 32) as u32;
                        let close_count = (op_pair & 0xFFFF_FFFF) as u32;
                        let read_count = (rw_pair >> 32) as u32;
                        let write_count = (rw_pair & 0xFFFF_FFFF) as u32;
                        println!(
                            "[SVC] fs ping ok (proto v{}) open={} read={} write={} close={}",
                            proto, open_count, read_count, write_count, close_count
                        );
                    } else {
                        println!(
                            "[SVC] fs ping unexpected status=0x{:x} proto={} op=0x{:x} rw=0x{:x}",
                            status, proto, op_pair, rw_pair
                        );
                    }
                }
                Err(e) => {
                    println!("[SVC] fs ping failed: {}", e);
                }
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
                        let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode
                            as sel4_sys::seL4_CPtr;
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
                            let auth =
                                sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadTCB as usize;
                            match p.set_priority(
                                auth.try_into().expect("auth fits"),
                                prio.try_into().expect("prio fits"),
                            ) {
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
                    if let Some(data) = self.read_file_via_fs(&path_str) {
                        final_data = Some(data);
                    } else if !path_str.contains("/bin/") {
                        let bin_path = alloc::format!("/bin/{}", filename);
                        final_data = self.read_file_via_fs(&bin_path);
                    }
                    if final_data.is_none() {
                        let vfs_lock = novafs_core::VFS.lock();
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

                        let env_vec: alloc::vec::Vec<alloc::string::String> = self
                            .env_vars
                            .iter()
                            .map(|(k, v)| alloc::format!("{}={}", k, v))
                            .collect();
                        let env_slice: alloc::vec::Vec<&str> =
                            env_vec.iter().map(|s| s.as_str()).collect();

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
                let filename = self.buffer[rest_start..end]
                    .iter()
                    .collect::<alloc::string::String>();
                let path_str = self.resolve_path(&filename);
                if let Some(fs_ep) = self.fs_endpoint() {
                    match fs_encrypt_direct(fs_ep, &path_str) {
                        0 => {
                            println!("File '{}' encrypted.", filename);
                            return;
                        }
                        1 => {
                            println!("File '{}' is already encrypted.", filename);
                            return;
                        }
                        e => println!("Failed to encrypt: {}", e),
                    }
                }
                if self.spawn_fs_helper("fs_encrypt", &path_str) {
                }
            }
        } else if self.word_eq(word_start, word_end, "decrypt") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: decrypt <file>");
            } else {
                let filename = self.buffer[rest_start..end]
                    .iter()
                    .collect::<alloc::string::String>();
                let path_str = self.resolve_path(&filename);
                if let Some(fs_ep) = self.fs_endpoint() {
                    match fs_decrypt_direct(fs_ep, &path_str) {
                        0 => {
                            println!("File '{}' decrypted.", filename);
                            return;
                        }
                        1 => {
                            println!("File '{}' is not encrypted.", filename);
                            return;
                        }
                        e => println!("Failed to decrypt: {}", e),
                    }
                }
                if self.spawn_fs_helper("fs_decrypt", &path_str) {
                }
            }
        } else if self.word_eq(word_start, word_end, "history") {
            self.print_history();
        } else if self.word_eq(word_start, word_end, "post") {
            if self.boot_info.is_null()
                || self.allocator.is_null()
                || self.slots.is_null()
                || self.frame_allocator.is_null()
            {
                println!("Cannot run POST: missing dependencies");
            } else {
                println!("Running POST (Power-On Self-Test)...");
                unsafe {
                    tests::run_all(
                        &*self.boot_info,
                        &mut *self.allocator,
                        &mut *self.slots,
                        &mut *self.frame_allocator,
                    )
                };
            }
        } else if self.word_eq(word_start, word_end, "runhello") {
            let data_opt = self.load_hello_binary();
            let env_vec = self.build_child_env(true);
            let env_slice: alloc::vec::Vec<&str> = env_vec.iter().map(|s| s.as_str()).collect();
            let arg_storage = if rest_start < end {
                let full_line = &self.buffer[rest_start..end];
                let full_line_str = full_line.iter().collect::<alloc::string::String>();
                full_line_str
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect::<alloc::vec::Vec<_>>()
            } else {
                alloc::vec::Vec::new()
            };
            let args: alloc::vec::Vec<&str> = arg_storage.iter().map(|s| s.as_str()).collect();

            if let Some(data) = data_opt {
                self.spawn_process("hello", &data, &args, &env_slice);
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

            if let Some(fs_ep) = self.fs_endpoint() {
                if fs_list_direct(fs_ep, &path_str) >= 0 {
                    return;
                }
            }
            if self.spawn_fs_helper("fs_ls", &path_str) {
                return;
            }

            println!("ls: filesystem not available");
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
                    let val = &s[idx + 1..];
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

                if let Some(fs_ep) = self.fs_endpoint() {
                    match fs_stat_direct(fs_ep, &path_str) {
                        1 => {
                            self.pending_cd_path = Some(path_str.clone());
                            return;
                        }
                        -2 => println!("cd: {}: No such file or directory", path_str),
                        _ => println!("cd: not a directory: {}", path_str),
                    }
                    return;
                }
                if self.spawn_fs_helper_args(&["fs_cd", &path_str]) {
                    self.pending_cd_path = Some(path_str);
                    return;
                }

                println!("cd: filesystem not available");
            }
        } else if self.word_eq(word_start, word_end, "mkdir") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: mkdir <dirname>");
            } else {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                let path_str = self.resolve_path(&s);

                let name = if let Some(idx) = path_str.rfind('/') {
                    &path_str[idx + 1..]
                } else {
                    path_str.as_str()
                };

                if name.is_empty() {
                    println!("mkdir: Invalid name");
                } else {
                    if let Some(fs_ep) = self.fs_endpoint() {
                        if fs_mkdir_direct(fs_ep, &path_str) >= 0 {
                            println!("[FS] mkdir ok");
                            return;
                        }
                    }
                    if self.spawn_fs_helper("fs_mkdir", &path_str) {
                        return;
                    }
                    println!("mkdir: filesystem not available");
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

                if let Some(fs_ep) = self.fs_endpoint() {
                    let fd = fs_open_direct(fs_ep, &path_str, 0);
                    if fd >= 0 {
                        let mut buf = vec![0u8; 4096];
                        let mut total = 0usize;
                        loop {
                            let n = fs_read_direct(fs_ep, fd as usize, &mut buf);
                            if n <= 0 {
                                break;
                            }
                            total += n as usize;
                            print!("{}", core::str::from_utf8(&buf[..n as usize]).unwrap_or("(binary)"));
                        }
                        if total == 0 || !buf[..1].ends_with(b"\n") {
                            println!();
                        }
                        fs_close_direct(fs_ep, fd as usize);
                        return;
                    }
                }
                if self.spawn_fs_helper("fs_cat", &path_str) {
                    return;
                }

                println!("cat: filesystem not available");
            }
        } else if self.word_eq(word_start, word_end, "rm") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: rm <path>");
            } else {
                let s = &self.buffer[rest_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                let path_str = self.resolve_path(&s);

                let name = if let Some(idx) = path_str.rfind('/') {
                    if idx == 0 {
                        &path_str[1..]
                    } else {
                        &path_str[idx + 1..]
                    }
                } else {
                    path_str.as_str()
                };

                if name.is_empty() || name == "." || name == ".." {
                    println!("rm: invalid argument");
                    return;
                }

                if let Some(fs_ep) = self.fs_endpoint() {
                    if fs_unlink_direct(fs_ep, &path_str) >= 0 {
                        println!("[FS] rm ok");
                        return;
                    }
                }
                if self.spawn_fs_helper("fs_rm", &path_str) {
                    return;
                }

                println!("rm: filesystem not available");
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

                    if let Some(fs_ep) = self.fs_endpoint() {
                        let src_fd = fs_open_direct(fs_ep, &src_path, 0);
                        if src_fd >= 0 {
                            let dest_fd = fs_open_direct(fs_ep, &dest_path, 1);
                            if dest_fd >= 0 {
                                let mut buf = vec![0u8; 4096];
                                let mut ok = true;
                                loop {
                                    let n = fs_read_direct(fs_ep, src_fd as usize, &mut buf);
                                    if n <= 0 {
                                        break;
                                    }
                                    if fs_write_direct(fs_ep, dest_fd as usize, &buf[..n as usize]) < 0 {
                                        ok = false;
                                        break;
                                    }
                                }
                                fs_close_direct(fs_ep, dest_fd as usize);
                                fs_close_direct(fs_ep, src_fd as usize);
                                if ok {
                                    println!("Copied '{}' to '{}'", src_path, dest_path);
                                    return;
                                }
                                println!("cp: write error");
                                return;
                            }
                            fs_close_direct(fs_ep, src_fd as usize);
                        }
                    }
                    let helper_args = ["fs_cp", src_path.as_str(), dest_path.as_str()];
                    if self.spawn_fs_helper_args(&helper_args) {
                        return;
                    }

                    println!("cp: filesystem not available");
                } else {
                    println!("Usage: cp <src> <dest>");
                }
            }
        } else if self.word_eq(word_start, word_end, "ln") {
        } else if self.word_eq(word_start, word_end, "ln") {
            let len = end - rest_start;
            if len == 0 {
                println!("Usage: ln [-s] <target> <link_name>");
            } else {
                let mut args_start = rest_start;
                let mut is_symlink = false;

                // Check for -s
                if end - rest_start >= 3
                    && self.buffer[rest_start] == '-'
                    && self.buffer[rest_start + 1] == 's'
                    && self.buffer[rest_start + 2] == ' '
                {
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

                    if is_symlink {
                        if let Some(fs_ep) = self.fs_endpoint() {
                            if fs_symlink_direct(fs_ep, &target_str, &link_path) >= 0 {
                                println!("Created symbolic link '{}' -> '{}'", link_path, target_str);
                                return;
                            }
                        }
                        let helper_args =
                            ["fs_symlink", target_str.as_str(), link_path.as_str()];
                        if self.spawn_fs_helper_args(&helper_args) {
                            return;
                        }
                        println!("ln: filesystem not available");
                    } else {
                        // Hard link creation
                        let target_path = self.resolve_path(&target_str);
                        if let Some(fs_ep) = self.fs_endpoint() {
                            if fs_link_direct(fs_ep, &target_path, &link_path) >= 0 {
                                println!("Created hard link '{}' => '{}'", link_path, target_path);
                                return;
                            }
                        }
                        let helper_args = ["fs_link", target_path.as_str(), link_path.as_str()];
                        if self.spawn_fs_helper_args(&helper_args) {
                            return;
                        }
                        println!("ln: filesystem not available");
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
                        if let Some(fs_ep) = self.fs_endpoint() {
                            if fs_chmod_direct(fs_ep, &path_str, mode) >= 0 {
                                println!("Changed mode of '{}' to {:o}", path_str, mode);
                                return;
                            }
                        }
                        if self.spawn_fs_helper_args(&["fs_chmod", &mode_str, &path_str]) {
                            return;
                        }
                        println!("chmod: filesystem not available");
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
                        if let (Ok(uid), Ok(gid)) =
                            (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                        {
                            let path_str = self.resolve_path(&file_str);
                            if let Some(fs_ep) = self.fs_endpoint() {
                                if fs_chown_direct(fs_ep, &path_str, uid, gid) >= 0 {
                                    println!("Changed ownership of '{}' to {}:{}", path_str, uid, gid);
                                    return;
                                }
                            }
                            if self.spawn_fs_helper_args(&["fs_chown", &owner_str, &path_str]) {
                                return;
                            }
                            println!("chown: filesystem not available");
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
                    let dest_path = self.resolve_path(&dest_str);

                    if let Some(fs_ep) = self.fs_endpoint() {
                        if fs_rename_direct(fs_ep, &src_path, &dest_path) >= 0 {
                            println!("Moved '{}' to '{}'", src_path, dest_path);
                            return;
                        }
                    }
                    let helper_args = ["fs_mv", src_path.as_str(), dest_path.as_str()];
                    if self.spawn_fs_helper_args(&helper_args) {
                        return;
                    }
                    println!("mv: filesystem not available");
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

                let name = if let Some(idx) = path_str.rfind('/') {
                    if idx == 0 {
                        &path_str[1..]
                    } else {
                        &path_str[idx + 1..]
                    }
                } else {
                    path_str.as_str()
                };

                if name.is_empty() {
                    println!("touch: Invalid name");
                    return;
                }

                if let Some(fs_ep) = self.fs_endpoint() {
                    let fd = fs_open_direct(fs_ep, &path_str, 1);
                    if fd >= 0 {
                        fs_close_direct(fs_ep, fd as usize);
                        println!("[FS] touch ok");
                        return;
                    }
                }
                if self.spawn_fs_helper("fs_touch", &path_str) {
                    return;
                }

                println!("touch: filesystem not available");
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
                    if let Some(fs_ep) = self.fs_endpoint() {
                        if fs_truncate_direct(fs_ep, &path_str, size) >= 0 {
                            println!("Truncated '{}' to {} bytes.", path_str, size);
                            return;
                        }
                    }
                    if self.spawn_fs_helper_args(&["fs_truncate", &path_str, size_str]) {
                        return;
                    }

                    println!("truncate: filesystem not available");
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
                    (
                        parts[0].to_string(),
                        parts[1].parse::<usize>().unwrap_or(100),
                    )
                } else if parts.len() == 1 {
                    (parts[0].to_string(), 100)
                } else {
                    ("test.dat".to_string(), 100)
                }
            };

            let path_str = self.resolve_path(&filename);
            println!("Writing {} KB to {}", size_kb, path_str);

            let size_str = size_kb.to_string();
            if let Some(fs_ep) = self.fs_endpoint() {
                if fs_writetest_direct(fs_ep, path_str.as_str(), size_kb) >= 0 {
                    println!("Write success");
                    self.mark_fs_service_dirty();
                    return;
                }
            }
            if self.spawn_fs_helper_args(&["fs_writetest", path_str.as_str(), size_str.as_str()]) {
                return;
            }

            let mut data = alloc::vec::Vec::with_capacity(size_kb * 1024);
            for i in 0..size_kb * 1024 {
                data.push((i % 256) as u8);
            }

            println!("writetest: filesystem not available");
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
                while fn_start < end && self.buffer[fn_start] == ' ' {
                    fn_start += 1;
                }

                let s = &self.buffer[fn_start..end];
                let s = s.iter().collect::<alloc::string::String>();
                let path_str = self.resolve_path(&s);

                let mut content_str = self.buffer[rest_start..content_end]
                    .iter()
                    .collect::<alloc::string::String>();
                if content_str.ends_with(' ') {
                    content_str.pop();
                }

                let content_bytes = content_str.as_bytes();
                if let Some(fs_ep) = self.fs_endpoint() {
                    let fd = fs_open_direct(fs_ep, &path_str, 1);
                    if fd >= 0 {
                        let ret = fs_write_direct(fs_ep, fd as usize, content_bytes);
                        fs_close_direct(fs_ep, fd as usize);
                        if ret >= 0 {
                            println!("Written to {}", path_str);
                            self.mark_fs_service_dirty();
                            return;
                        }
                    }
                }
                let helper_args = ["fs_write", path_str.as_str(), content_str.as_str()];
                if self.spawn_fs_helper_args(&helper_args) {
                    return;
                }

                let mut content_vec = alloc::vec::Vec::new();
                for c in content_str.chars() {
                    let mut b = [0; 4];
                    let s = c.encode_utf8(&mut b);
                    content_vec.extend_from_slice(s.as_bytes());
                }

                println!("echo: filesystem not available");
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

    fn spawn_process(
        &mut self,
        name: &str,
        elf_data: &[u8],
        args: &[&str],
        env: &[&str],
    ) -> Option<usize> {
        if self.boot_info.is_null()
            || self.allocator.is_null()
            || self.slots.is_null()
            || self.frame_allocator.is_null()
        {
            println!("spawn_process: unavailable");
            return None;
        }

        use crate::process::{get_process_manager, Process, MAX_PROCESSES};
        use sel4_sys::*;

        let bi = unsafe { &*self.boot_info };
        let alloc = unsafe { &mut *self.allocator };
        let slots = unsafe { &mut *self.slots };
        let frame_alloc = unsafe { &mut *self.frame_allocator };

        // 1. Allocate PID.
        // Keep PID 0 reserved for the initial integration-suite role to avoid
        // accidentally re-triggering full /bin/hello test flow from shell commands.
        let mut pm = get_process_manager();
        let pid = (1..MAX_PROCESSES)
            .find(|candidate| pm.get_process(*candidate).is_none())
            .unwrap_or(MAX_PROCESSES);
        if pid == MAX_PROCESSES {
            println!("[RUN] Failed to allocate PID: no non-zero PID available");
            return None;
        }

        let badge = 100 + pid;

        // 2. Mint Badged Endpoint
        let badged_ep_slot = match slots.alloc() {
            Ok(s) => s,
            Err(_) => {
                println!("[RUN] Failed to allocate slot for badged EP");
                return None;
            }
        };

        let root_cnode_cap = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
        let root_cnode = libnova::cap::CNode::new(root_cnode_cap, seL4_WordBits as u8);

        if let Err(e) = root_cnode.mint(
            badged_ep_slot,
            &root_cnode,
            self.syscall_ep_cap,
            cap_rights_new(false, true, true, true),
            badge as seL4_Word,
        ) {
            println!("[RUN] Failed to mint badged endpoint: {:?}", e);
            slots.free(badged_ep_slot);
            return None;
        }

        println!("[RUN] Spawning process '{}' (PID {})...", name, pid);

        // 3. Spawn Process
        match Process::spawn(
            alloc,
            slots,
            frame_alloc,
            bi,
            name,
            elf_data,
            args,
            env,
            100,
            badged_ep_slot,
            32,
            0,
            0,
        ) {
            Ok(process) => {
                // 4. Add to Manager
                if let Err(e) = pm.add_process_at(pid, process) {
                    println!("[RUN] Failed to add process to manager: {:?}", e);
                    None
                } else {
                    println!("[RUN] Process spawned successfully (PID {}).", pid);
                    Some(pid)
                }
            }
            Err(e) => {
                println!("[RUN] Spawn failed: {:?}", e);
                None
            }
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
