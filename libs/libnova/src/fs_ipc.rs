use sel4_sys::seL4_Word;

pub const FS_LABEL_OPEN: seL4_Word = 20;
pub const FS_LABEL_READ: seL4_Word = 21;
pub const FS_LABEL_WRITE: seL4_Word = 22;
pub const FS_LABEL_CLOSE: seL4_Word = 23;
pub const FS_LABEL_PING: seL4_Word = 0xF500;

pub const FS_STATUS_READY: seL4_Word = 0x4653_5256;
pub const FS_PROTO_V1: seL4_Word = 1;

pub const FS_ERR_NOT_IMPLEMENTED: i64 = -38;

#[inline]
pub const fn fs_err_not_implemented_word() -> seL4_Word {
    FS_ERR_NOT_IMPLEMENTED as seL4_Word
}

#[inline]
pub const fn is_not_implemented(word: seL4_Word) -> bool {
    word as i64 == FS_ERR_NOT_IMPLEMENTED
}
