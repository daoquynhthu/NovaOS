#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Backspace,
    Tab,
    Left,
    Right,
    Up,
    Down,
    Delete,
    Home,
    End,
    PageUp,
    PageDown,
}

pub struct Keyboard {
    extended: bool,
    lshift: bool,
    rshift: bool,
    lctrl: bool,
    rctrl: bool,
    caps_lock: bool,
}

impl Keyboard {
    pub fn new() -> Self {
        Keyboard {
            extended: false,
            lshift: false,
            rshift: false,
            lctrl: false,
            rctrl: false,
            caps_lock: false,
        }
    }

    pub fn process_scancode(&mut self, scancode: u8) -> Option<Key> {
        // Handle Extended scancodes (0xE0 prefix)
        if scancode == 0xE0 {
            self.extended = true;
            return None;
        }

        let extended = self.extended;
        self.extended = false;

        if scancode & 0x80 != 0 {
            let key = scancode & 0x7F;
            if extended {
                if key == 0x1D {
                    self.rctrl = false;
                }
            } else {
                match key {
                    0x2A => self.lshift = false,
                    0x36 => self.rshift = false,
                    0x1D => self.lctrl = false,
                    _ => {}
                }
            }
            return None;
        }

        if extended {
            let k = match scancode {
                0x1D => {
                    self.rctrl = true;
                    return None;
                }
                0x48 => Key::Up,
                0x50 => Key::Down,
                0x4B => Key::Left,
                0x4D => Key::Right,
                0x53 => Key::Delete,
                0x47 => Key::Home,
                0x4F => Key::End,
                0x49 => Key::PageUp,
                0x51 => Key::PageDown,
                _ => return None,
            };
            return Some(k);
        }

        // Handle Make codes (Key Press)
        match scancode {
            0x2A => { self.lshift = true; return None; }
            0x36 => { self.rshift = true; return None; }
            0x1D => { self.lctrl = true; return None; }
            0x3A => { self.caps_lock = !self.caps_lock; return None; }
            _ => {}
        }

        let shift = self.lshift || self.rshift;
        // Simple mapping for common keys
        let key = match scancode {
            0x02 => if shift { '!' } else { '1' },
            0x03 => if shift { '@' } else { '2' },
            0x04 => if shift { '#' } else { '3' },
            0x05 => if shift { '$' } else { '4' },
            0x06 => if shift { '%' } else { '5' },
            0x07 => if shift { '^' } else { '6' },
            0x08 => if shift { '&' } else { '7' },
            0x09 => if shift { '*' } else { '8' },
            0x0A => if shift { '(' } else { '9' },
            0x0B => if shift { ')' } else { '0' },
            0x0C => if shift { '_' } else { '-' },
            0x0D => if shift { '+' } else { '=' },
            0x0E => return Some(Key::Backspace),
            0x0F => return Some(Key::Tab),
            0x10 => if shift { 'Q' } else { 'q' },
            0x11 => if shift { 'W' } else { 'w' },
            0x12 => if shift { 'E' } else { 'e' },
            0x13 => if shift { 'R' } else { 'r' },
            0x14 => if shift { 'T' } else { 't' },
            0x15 => if shift { 'Y' } else { 'y' },
            0x16 => if shift { 'U' } else { 'u' },
            0x17 => if shift { 'I' } else { 'i' },
            0x18 => if shift { 'O' } else { 'o' },
            0x19 => if shift { 'P' } else { 'p' },
            0x1A => if shift { '{' } else { '[' },
            0x1B => if shift { '}' } else { ']' },
            0x1C => return Some(Key::Enter),
            0x1E => if shift { 'A' } else { 'a' },
            0x1F => if shift { 'S' } else { 's' },
            0x20 => if shift { 'D' } else { 'd' },
            0x21 => if shift { 'F' } else { 'f' },
            0x22 => if shift { 'G' } else { 'g' },
            0x23 => if shift { 'H' } else { 'h' },
            0x24 => if shift { 'J' } else { 'j' },
            0x25 => if shift { 'K' } else { 'k' },
            0x26 => if shift { 'L' } else { 'l' },
            0x27 => if shift { ':' } else { ';' },
            0x28 => if shift { '"' } else { '\'' },
            0x29 => if shift { '~' } else { '`' },
            0x2B => if shift { '|' } else { '\\' },
            0x2C => if shift { 'Z' } else { 'z' },
            0x2D => if shift { 'X' } else { 'x' },
            0x2E => if shift { 'C' } else { 'c' },
            0x2F => if shift { 'V' } else { 'v' },
            0x30 => if shift { 'B' } else { 'b' },
            0x31 => if shift { 'N' } else { 'n' },
            0x32 => if shift { 'M' } else { 'm' },
            0x33 => if shift { '<' } else { ',' },
            0x34 => if shift { '>' } else { '.' },
            0x35 => if shift { '?' } else { '/' },
            0x39 => ' ',    // Space
            _ => return None,
        };

        // Apply Caps Lock (only affects letters)
        let mut char_code = key;
        let is_letter = char_code.is_ascii_lowercase() || char_code.is_ascii_uppercase();
        if self.caps_lock && is_letter {
            if char_code.is_ascii_lowercase() {
                char_code = char_code.to_ascii_uppercase();
            } else {
                char_code = char_code.to_ascii_lowercase();
            }
        }

        let ctrl = self.lctrl || self.rctrl;
        if ctrl && is_letter {
            let lower = char_code.to_ascii_lowercase() as u8;
            if lower.is_ascii_lowercase() {
                let c = (lower - b'a' + 1) as char;
                return Some(Key::Char(c));
            }
        }

        Some(Key::Char(char_code))
    }
}
