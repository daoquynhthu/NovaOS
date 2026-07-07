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
}
