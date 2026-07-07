//! Input validation helpers for syscall handlers.
//!
//! These functions are pure logic (no seL4 side effects) and can be tested
//! on the host target.

use crate::ipc::MessageInfo;

const MAX_MSG_REGISTERS: usize = 120;
const MAX_EXTRA_CAPS: usize = 3;

/// Error returned when a syscall message is malformed or out of bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateError {
    MessageLengthTooLarge,
    MessageTooShort,
    MessageRegisterIndexOutOfRange,
    CapabilityIndexOutOfRange,
}

/// Validate that the message length declared in `info` does not exceed the
/// architecture's message-register array.
pub fn validate_message_length(info: &MessageInfo) -> Result<(), ValidateError> {
    if (info.length() as usize) > MAX_MSG_REGISTERS {
        return Err(ValidateError::MessageLengthTooLarge);
    }
    Ok(())
}

/// Validate that `idx` is a valid message-register index for this message.
pub fn validate_mr_index(info: &MessageInfo, idx: usize) -> Result<(), ValidateError> {
    if idx >= (info.length() as usize) {
        return Err(ValidateError::MessageRegisterIndexOutOfRange);
    }
    Ok(())
}

/// Validate that `cap_idx` is a valid extra-capability index.
pub fn validate_cap_index(info: &MessageInfo, cap_idx: usize) -> Result<(), ValidateError> {
    if cap_idx >= MAX_EXTRA_CAPS {
        return Err(ValidateError::CapabilityIndexOutOfRange);
    }
    if (info.extra_caps() as usize) <= cap_idx {
        return Err(ValidateError::CapabilityIndexOutOfRange);
    }
    Ok(())
}

/// Validate that a request has at least `min_words` message registers.
pub fn validate_fs_request_min(info: &MessageInfo, min_words: usize) -> Result<(), ValidateError> {
    let len = info.length() as usize;
    if len < min_words {
        return Err(ValidateError::MessageTooShort);
    }
    validate_message_length(info)
}

/// Return the minimum required message length for a given fs_server protocol label.
pub const fn fs_min_words(label: u64) -> usize {
    use crate::fs_ipc::FsLabel;
    match FsLabel::from_u64(label) {
        Some(FsLabel::Ping) | Some(FsLabel::Refresh) | Some(FsLabel::Sync) => 0,
        Some(FsLabel::Close) | Some(FsLabel::Unlink) | Some(FsLabel::Mkdir) | Some(FsLabel::List) | Some(FsLabel::Stat) | Some(FsLabel::Encrypt) | Some(FsLabel::Decrypt) => 1,
        Some(FsLabel::Read) | Some(FsLabel::Write) | Some(FsLabel::Open) | Some(FsLabel::Truncate) | Some(FsLabel::Chmod) | Some(FsLabel::Rename) | Some(FsLabel::Link) | Some(FsLabel::Symlink) | Some(FsLabel::Writetest) => 2,
        Some(FsLabel::Chown) => 3,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_length_within_bounds_ok() {
        let info = MessageInfo::new(0, 0, 0, 4);
        assert_eq!(validate_message_length(&info), Ok(()));
    }

    #[test]
    fn message_length_too_large_fails() {
        let info = MessageInfo::new(0, 0, 0, (MAX_MSG_REGISTERS + 1) as u64);
        assert_eq!(
            validate_message_length(&info),
            Err(ValidateError::MessageLengthTooLarge)
        );
    }

    #[test]
    fn mr_index_within_message_ok() {
        let info = MessageInfo::new(0, 0, 0, 4);
        assert_eq!(validate_mr_index(&info, 3), Ok(()));
    }

    #[test]
    fn mr_index_out_of_range_fails() {
        let info = MessageInfo::new(0, 0, 0, 4);
        assert_eq!(
            validate_mr_index(&info, 4),
            Err(ValidateError::MessageRegisterIndexOutOfRange)
        );
    }

    #[test]
    fn cap_index_with_extra_caps_ok() {
        let info = MessageInfo::new(0, 0, 2, 0);
        assert_eq!(validate_cap_index(&info, 0), Ok(()));
        assert_eq!(validate_cap_index(&info, 1), Ok(()));
    }

    #[test]
    fn cap_index_without_extra_caps_fails() {
        let info = MessageInfo::new(0, 0, 0, 0);
        assert_eq!(
            validate_cap_index(&info, 0),
            Err(ValidateError::CapabilityIndexOutOfRange)
        );
    }

    #[test]
    fn cap_index_beyond_max_fails() {
        let info = MessageInfo::new(0, 0, 3, 0);
        assert_eq!(
            validate_cap_index(&info, 3),
            Err(ValidateError::CapabilityIndexOutOfRange)
        );
    }

    #[test]
    fn fs_min_words_ping_zero() {
        assert_eq!(fs_min_words(0xF500), 0);
    }

    #[test]
    fn fs_min_words_open_two() {
        // FsLabel::Open = 20
        assert_eq!(fs_min_words(20), 2);
    }

    #[test]
    fn fs_min_words_chown_three() {
        // FsLabel::Chown = 32
        assert_eq!(fs_min_words(32), 3);
    }

    #[test]
    fn fs_min_words_unknown_zero() {
        assert_eq!(fs_min_words(99), 0);
    }

    #[test]
    fn validate_fs_request_too_short_fails() {
        let info = MessageInfo::new(20, 0, 0, 1); // Open needs at least 2 words
        assert_eq!(
            validate_fs_request_min(&info, 2),
            Err(ValidateError::MessageTooShort)
        );
    }

    #[test]
    fn validate_fs_request_at_min_ok() {
        let info = MessageInfo::new(20, 0, 0, 2); // Open with exactly 2 words
        assert_eq!(validate_fs_request_min(&info, 2), Ok(()));
    }
}
