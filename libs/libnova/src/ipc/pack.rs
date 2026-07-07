//! Bounded IPC message packing/unpacking helpers.
//!
//! Built on top of the raw `crate::ipc::{set_mr, get_mr}` primitives.
//! All operations carry an explicit word-level bound and return `BoundError`
//! instead of panicking or reading/writing past the message register array.

use super::{get_mr, set_mr};
use sel4_sys::seL4_Word;

/// Error returned when a packing or unpacking operation would exceed the
/// declared message-register bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundError {
    OutOfBounds,
}

/// Writes words and byte payloads into the current thread's seL4 IPC buffer.
pub struct MessageWriter {
    cursor: usize,
    max_words: usize,
}

impl MessageWriter {
    /// Create a writer starting at MR 0 with the given word limit.
    pub fn new(max_words: usize) -> Self {
        Self {
            cursor: 0,
            max_words,
        }
    }

    /// Create a writer starting at an arbitrary MR offset.
    pub fn with_cursor(cursor: usize, max_words: usize) -> Self {
        Self { cursor, max_words }
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn max_words(&self) -> usize {
        self.max_words
    }

    pub fn remaining(&self) -> usize {
        self.max_words.saturating_sub(self.cursor)
    }

    /// Write a single `u64` word.
    pub fn write_u64(&mut self, value: u64) -> Result<(), BoundError> {
        if self.cursor >= self.max_words {
            return Err(BoundError::OutOfBounds);
        }
        set_mr(self.cursor, value as seL4_Word);
        self.cursor += 1;
        Ok(())
    }

    /// Write a single `usize` word.
    pub fn write_usize(&mut self, value: usize) -> Result<(), BoundError> {
        self.write_u64(value as u64)
    }

    /// Pack a byte slice into little-endian words.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), BoundError> {
        let words_needed = bytes.len().div_ceil(8);
        if words_needed > self.remaining() {
            return Err(BoundError::OutOfBounds);
        }
        for chunk in bytes.chunks(8) {
            let mut word = 0u64;
            for (i, &b) in chunk.iter().enumerate() {
                word |= (b as u64) << (i * 8);
            }
            set_mr(self.cursor, word as seL4_Word);
            self.cursor += 1;
        }
        Ok(())
    }

    /// Write a length-prefixed byte slice: first `usize` length, then the bytes.
    pub fn write_len_prefixed_bytes(&mut self, bytes: &[u8]) -> Result<(), BoundError> {
        self.write_usize(bytes.len())?;
        self.write_bytes(bytes)
    }
}

/// Reads words and byte payloads from the current thread's seL4 IPC buffer.
pub struct MessageReader {
    cursor: usize,
    length: usize,
}

impl MessageReader {
    /// Create a reader starting at MR 0 limited to `length` words.
    pub fn new(length: usize) -> Self {
        Self { cursor: 0, length }
    }

    /// Create a reader starting at an arbitrary MR offset.
    pub fn with_cursor(cursor: usize, length: usize) -> Self {
        Self { cursor, length }
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn remaining(&self) -> usize {
        self.length.saturating_sub(self.cursor)
    }

    /// Read a single `u64` word.
    pub fn read_u64(&mut self) -> Result<u64, BoundError> {
        if self.cursor >= self.length {
            return Err(BoundError::OutOfBounds);
        }
        let value = get_mr(self.cursor) as u64;
        self.cursor += 1;
        Ok(value)
    }

    /// Read a single `usize` word.
    pub fn read_usize(&mut self) -> Result<usize, BoundError> {
        self.read_u64().map(|v| v as usize)
    }

    /// Unpack little-endian words into the provided buffer.
    pub fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), BoundError> {
        let words_needed = out.len().div_ceil(8);
        if words_needed > self.remaining() {
            return Err(BoundError::OutOfBounds);
        }
        for (i, dst) in out.iter_mut().enumerate() {
            let word = get_mr(self.cursor + (i / 8));
            let shift = (i % 8) * 8;
            *dst = ((word >> shift) & 0xFF) as u8;
        }
        self.cursor += words_needed;
        Ok(())
    }

    /// Read a length-prefixed byte slice into `out` and return the valid sub-slice.
    pub fn read_len_prefixed_bytes<'a>(
        &mut self,
        out: &'a mut [u8],
    ) -> Result<&'a [u8], BoundError> {
        let len = self.read_usize()?;
        if len > out.len() {
            return Err(BoundError::OutOfBounds);
        }
        self.read_bytes(&mut out[..len])?;
        Ok(&out[..len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sel4_sys::{seL4_IPCBuffer, seL4_MsgLimits};

    fn with_ipc_buffer<T>(f: impl FnOnce() -> T) -> T {
        let mut buf = unsafe { core::mem::MaybeUninit::<seL4_IPCBuffer>::zeroed().assume_init() };
        unsafe {
            sel4_sys::__sel4_ipc_buffer = &mut buf;
        }
        let result = f();
        unsafe {
            sel4_sys::__sel4_ipc_buffer = core::ptr::null_mut();
        }
        result
    }

    #[test]
    fn writer_write_u64_roundtrip() {
        with_ipc_buffer(|| {
            let mut w = MessageWriter::new(4);
            w.write_u64(0x1234_5678_9ABC_DEF0).unwrap();
            w.write_u64(0x0FED_CBA9_8765_4321).unwrap();
            assert_eq!(w.cursor(), 2);

            let mut r = MessageReader::new(4);
            assert_eq!(r.read_u64().unwrap(), 0x1234_5678_9ABC_DEF0);
            assert_eq!(r.read_u64().unwrap(), 0x0FED_CBA9_8765_4321);
        });
    }

    #[test]
    fn writer_write_bytes_roundtrip() {
        with_ipc_buffer(|| {
            let data = b"Hello, NovaOS!";
            let mut w = MessageWriter::new(4);
            w.write_bytes(data).unwrap();
            assert_eq!(w.cursor(), data.len().div_ceil(8));

            let mut r = MessageReader::new(w.cursor());
            let mut out = [0u8; 32];
            r.read_bytes(&mut out[..data.len()]).unwrap();
            assert_eq!(&out[..data.len()], data.as_slice());
        });
    }

    #[test]
    fn writer_len_prefixed_bytes_roundtrip() {
        with_ipc_buffer(|| {
            let data = b"path/to/file";
            let mut w = MessageWriter::new(4);
            w.write_len_prefixed_bytes(data).unwrap();

            let mut r = MessageReader::new(w.cursor());
            let mut out = [0u8; 64];
            let got = r.read_len_prefixed_bytes(&mut out).unwrap();
            assert_eq!(got, data.as_slice());
        });
    }

    #[test]
    fn writer_out_of_bounds_rejected() {
        with_ipc_buffer(|| {
            let mut w = MessageWriter::new(1);
            assert_eq!(w.write_u64(1).unwrap(), ());
            assert_eq!(w.write_u64(2).unwrap_err(), BoundError::OutOfBounds);
        });
    }

    #[test]
    fn writer_bytes_out_of_bounds_rejected() {
        with_ipc_buffer(|| {
            let mut w = MessageWriter::new(1);
            // 16 bytes need 2 words, only 1 available
            assert_eq!(
                w.write_bytes(&[0u8; 16]).unwrap_err(),
                BoundError::OutOfBounds
            );
        });
    }

    #[test]
    fn reader_out_of_bounds_rejected() {
        with_ipc_buffer(|| {
            let mut r = MessageReader::new(0);
            assert_eq!(r.read_u64().unwrap_err(), BoundError::OutOfBounds);
        });
    }

    #[test]
    fn reader_bytes_out_of_bounds_rejected() {
        with_ipc_buffer(|| {
            // Only one word available, but caller asks for 16 bytes
            let mut r = MessageReader::new(1);
            let mut out = [0u8; 16];
            assert_eq!(r.read_bytes(&mut out).unwrap_err(), BoundError::OutOfBounds);
        });
    }

    #[test]
    fn reader_len_prefixed_truncated_rejected() {
        with_ipc_buffer(|| {
            // Writer claims 8 bytes but only provides 1 word (8 bytes) including length word,
            // so payload is short.
            let mut w = MessageWriter::new(4);
            w.write_usize(16).unwrap(); // claim 16 bytes
            w.write_bytes(&[0u8; 8]).unwrap(); // only 8 bytes available
            let cursor = w.cursor();

            let mut r = MessageReader::new(cursor);
            let mut out = [0u8; 32];
            assert_eq!(
                r.read_len_prefixed_bytes(&mut out).unwrap_err(),
                BoundError::OutOfBounds
            );
        });
    }

    #[test]
    fn writer_uses_max_length_default() {
        with_ipc_buffer(|| {
            let mut w = MessageWriter::new(seL4_MsgLimits::seL4_MsgMaxLength as usize);
            // Should not fail for a payload that fits in the maximum MR array.
            w.write_bytes(&[0u8; 64]).unwrap();
        });
    }
}
