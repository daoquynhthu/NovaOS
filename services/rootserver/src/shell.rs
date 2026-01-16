use crate::{print, println};
use crate::keyboard::Key;
use crate::memory::{SlotAllocator, UntypedAllocator};
use crate::tests;
use sel4_sys::seL4_BootInfo;

const MAX_CMD_LEN: usize = 64;
const HISTORY_LEN: usize = 16;
pub(crate) const USER_HELLO_ELF: &[u8] = include_bytes!("../../../target/x86_64-unknown-none/release/user_app");

pub struct Shell {
    buffer: [char; MAX_CMD_LEN],
    len: usize,
    cursor: usize,
    boot_info: *const seL4_BootInfo,
    allocator: *mut UntypedAllocator,
    slots: *mut SlotAllocator,
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
}

impl Shell {
    pub fn new() -> Self {
        Shell {
            buffer: ['\0'; MAX_CMD_LEN],
            len: 0,
            cursor: 0,
            boot_info: core::ptr::null(),
            allocator: core::ptr::null_mut(),
            slots: core::ptr::null_mut(),
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
        }
    }

    pub fn init(
        &mut self,
        boot_info: &seL4_BootInfo,
        allocator: &mut UntypedAllocator,
        slots: &mut SlotAllocator,
        syscall_ep_cap: sel4_sys::seL4_CPtr,
    ) {
        self.boot_info = boot_info as *const seL4_BootInfo;
        self.allocator = allocator as *mut UntypedAllocator;
        self.slots = slots as *mut SlotAllocator;
        self.syscall_ep_cap = syscall_ep_cap;
        println!("\n[SHELL] Ready. Type 'help' for commands.");
        print!("NovaOS> ");
    }

    pub fn on_key(&mut self, k: Key) {
        match k {
            Key::Enter => {
                println!();
                self.history_view = None;
                self.draft_valid = false;
                self.execute_command();
                self.clear_line();
                print!("NovaOS> ");
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
            Key::Tab => self.insert_char('\t'),
            Key::Up => self.history_up(),
            Key::Down => self.history_down(),
            Key::PageUp | Key::PageDown => {}
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
            println!("  whoami    - Show user info");
            println!("  status    - Show system status");
            println!("  bootinfo  - Show seL4 BootInfo summary");
            println!("  alloc     - Show allocator summary");
            println!("  meminfo   - Show memory usage summary");
            println!("  ps        - List tracked processes");
            println!("  history   - Show recent commands");
            println!("  post      - Run POST tests again");
            println!("  runhello  - Run minimal user-mode program");
        } else if self.word_eq(word_start, word_end, "clear") {
            print!("\x1b[2J\x1b[1;1H");
        } else if self.word_eq(word_start, word_end, "whoami") {
            println!("root");
        } else if self.word_eq(word_start, word_end, "status") {
            println!("System: NovaOS v0.0.1-alpha");
            println!("Mode:   x86_64 Long Mode");
            println!("Driver: Keyboard, Serial(COM1), ACPI, IOAPIC");
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
            for (pid, slot) in pm.processes.iter().enumerate() {
                if let Some(p) = slot {
                    any = true;
                    println!("PID {}: TCB={}, PML4={}, State={:?}", pid, p.tcb_cap, p.vspace.pml4_cap, p.state);
                }
            }
            if !any {
                println!("No processes tracked.");
            }
        } else if self.word_eq(word_start, word_end, "history") {
            self.print_history();
        } else if self.word_eq(word_start, word_end, "post") {
            if self.boot_info.is_null() || self.allocator.is_null() || self.slots.is_null() {
                println!("POST: unavailable");
            } else {
                unsafe { tests::run_all(&*self.boot_info, &mut *self.allocator, &mut *self.slots) };
                println!("[POST] Done.");
            }
        } else if self.word_eq(word_start, word_end, "runhello") {
            if self.boot_info.is_null() || self.allocator.is_null() || self.slots.is_null() {
                println!("runhello: unavailable");
            } else {
                use crate::process::{Process, get_process_manager};
                use sel4_sys::*;

                let bi = unsafe { &*self.boot_info };
                let alloc = unsafe { &mut *self.allocator };
                let slots = unsafe { &mut *self.slots };

                // 1. Allocate PID
                let pm = get_process_manager();
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

                let root_cnode = seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as seL4_CPtr;
                let cnode_depth = seL4_WordBits; 
                
                let err = unsafe {
                    seL4_CNode_Mint(
                        root_cnode,
                        badged_ep_slot,
                        cnode_depth as u8,
                        root_cnode,
                        self.syscall_ep_cap,
                        cnode_depth as u8,
                        crate::utils::seL4_CapRights_new(0, 1, 1, 1),
                        badge as seL4_Word 
                    )
                };
                
                if err != 0.into() {
                println!("[RUN] Failed to mint badged endpoint: {:?}", err);
                return;
            }

                println!("[RUN] Spawning process PID {} with Badge {}...", pid, badge);

                // 3. Spawn Process
                match Process::spawn(alloc, slots, bi, USER_HELLO_ELF, 100, badged_ep_slot) {
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
        } else if self.word_eq(word_start, word_end, "echo") {
            if rest_start >= end {
                println!();
            } else {
                for i in rest_start..end {
                    print!("{}", self.buffer[i]);
                }
                println!();
            }
        } else {
             print!("Unknown command: ");
            for i in word_start..word_end {
                print!("{}", self.buffer[i]);
            }
            println!();
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
