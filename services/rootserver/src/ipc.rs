use sel4_sys::*;

#[derive(Debug)]
pub struct Endpoint {
    pub cptr: seL4_CPtr,
}

impl Endpoint {
    pub fn new(cptr: seL4_CPtr) -> Self {
        Endpoint { cptr }
    }

    pub fn reply_recv_with_mrs(&self, info: seL4_MessageInfo, mrs: [u64; 4]) -> (seL4_MessageInfo, seL4_Word, [u64; 4]) {
        unsafe {
            let mut sender_badge: seL4_Word = 0;
            let (resp_info, mr0, mr1, mr2, mr3) = sel4_sys::seL4_ReplyRecvWithMRs(
                self.cptr,
                info,
                &mut sender_badge,
                mrs[0].try_into().unwrap(), mrs[1].try_into().unwrap(), mrs[2].try_into().unwrap(), mrs[3].try_into().unwrap()
            );
            (resp_info, sender_badge, [mr0.into(), mr1.into(), mr2.into(), mr3.into()])
        }
    }

    /// 发送消息并等待回复 (Client Side)
    /// 
    /// # Arguments
    /// * `msg` - 要发送的一个 u64 数据 (为了简化测试，只传一个字)
    /// 
    /// # Returns
    /// * `Ok(u64)` - 接收到的回复数据
    pub fn call(&self, msg: u64) -> u64 {
        unsafe {
            let info = seL4_MessageInfo_new(
                0, // label
                0, // capsUnwrapped
                0, // extraCaps
                1, // length (1 word)
            );

            // Use seL4_CallWithMRs to avoid global IPC buffer dependency
            let (resp_info, _badge, mr0, _mr1, _mr2, _mr3) = sel4_sys::seL4_CallWithMRs(
                self.cptr,
                info,
                msg.try_into().unwrap(), // MR0
                0, 0, 0 // MR1-MR3
            );
            
            // Check length of response
            let len = seL4_MessageInfo_get_length(resp_info);
            if len > 0 {
                return mr0.into();
            }
            0
        }
    }

    /// 接收消息 (Server Side)
    /// 
    /// # Returns
    /// * `(u64, seL4_CPtr)` - (接收到的数据, 发送者的 reply cap)
    pub fn recv(&self) -> (u64, seL4_Word) {
        unsafe {
            let mut sender_badge: seL4_Word = 0;
            
            // Use seL4_RecvWithMRs
            let (info, mr0, _mr1, _mr2, _mr3) = sel4_sys::seL4_RecvWithMRs(
                self.cptr, 
                &mut sender_badge
            );
            
            let len = seL4_MessageInfo_get_length(info);
            let msg = if len > 0 { mr0 } else { 0 };
            
            (msg.into(), sender_badge)
        }
    }

    pub fn recv_with_mrs(&self) -> (seL4_MessageInfo, seL4_Word, [u64; 4]) {
        unsafe {
            let mut sender_badge: seL4_Word = 0;
            let (info, mr0, mr1, mr2, mr3) = sel4_sys::seL4_RecvWithMRs(
                self.cptr, 
                &mut sender_badge
            );
            (info, sender_badge, [mr0.into(), mr1.into(), mr2.into(), mr3.into()])
        }
    }



    /// 回复并等待下一个消息 (Server Loop)
    /// 
    /// # Arguments
    /// * `msg` - 回复的数据
    pub fn reply_recv(&self, msg: u64) -> (u64, seL4_Word) {
        unsafe {
            let info = seL4_MessageInfo_new(
                0, 0, 0, 1
            );
            
            let mut sender_badge: seL4_Word = 0;
            
            // Use seL4_ReplyRecvWithMRs
            let (resp_info, mr0, _mr1, _mr2, _mr3) = sel4_sys::seL4_ReplyRecvWithMRs(
                self.cptr,
                info,
                &mut sender_badge,
                msg.try_into().unwrap(), // MR0
                0, 0, 0 // MR1-MR3
            );
            
            let len = seL4_MessageInfo_get_length(resp_info);
            let next_msg = if len > 0 { mr0 } else { 0 };
            
            (next_msg.into(), sender_badge)
        }
    }
}
