use sel4_sys::*;

#[derive(Clone, Copy)]
pub struct MessageInfo {
    pub inner: seL4_MessageInfo,
}

impl MessageInfo {
    pub fn new(label: seL4_Word, caps_unwrapped: seL4_Word, extra_caps: seL4_Word, length: seL4_Word) -> Self {
        MessageInfo {
            inner: seL4_MessageInfo_new(label, caps_unwrapped, extra_caps, length),
        }
    }

    pub fn label(&self) -> seL4_Word {
        seL4_MessageInfo_get_label(self.inner)
    }

    pub fn length(&self) -> seL4_Word {
        seL4_MessageInfo_get_length(self.inner)
    }
}

pub fn call(dest: seL4_CPtr, info: MessageInfo) -> MessageInfo {
    unsafe {
        MessageInfo {
            inner: seL4_Call(dest, info.inner),
        }
    }
}

pub fn send(dest: seL4_CPtr, info: MessageInfo) {
    unsafe {
        seL4_Send(dest, info.inner);
    }
}

pub fn reply(info: MessageInfo) {
    unsafe {
        seL4_Reply(info.inner);
    }
}

pub fn recv(src: seL4_CPtr) -> (seL4_Word, MessageInfo) {
    unsafe {
        let mut sender: seL4_Word = 0;
        let info = seL4_Recv(src, &mut sender);
        (sender, MessageInfo { inner: info })
    }
}

pub fn reply_recv(src: seL4_CPtr, info: MessageInfo) -> (seL4_Word, MessageInfo) {
    unsafe {
        let mut sender: seL4_Word = 0;
        let info = seL4_ReplyRecv(src, info.inner, &mut sender);
        (sender, MessageInfo { inner: info })
    }
}

pub fn wait(src: seL4_CPtr) -> seL4_Word {
    unsafe {
        let mut badge: seL4_Word = 0;
        seL4_Wait(src, &mut badge);
        badge
    }
}

pub fn set_mr(i: usize, value: seL4_Word) {
    unsafe {
        seL4_SetMR(i, value);
    }
}

pub fn get_mr(i: usize) -> seL4_Word {
    unsafe {
        seL4_GetMR(i)
    }
}

pub fn set_cap(i: usize, cap: seL4_CPtr) {
    unsafe {
        seL4_SetCap_My(i, cap);
    }
}

pub fn set_cap_receive_path(root: seL4_CPtr, cap: seL4_CPtr, depth: seL4_Word) {
    unsafe {
        let ipc_buffer = seL4_GetIPCBuffer();
        if !ipc_buffer.is_null() {
            (*ipc_buffer).receiveCNode = root;
            (*ipc_buffer).receiveIndex = cap;
            (*ipc_buffer).receiveDepth = depth;
        }
    }
}
