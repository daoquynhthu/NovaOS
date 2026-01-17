use sel4_sys::{seL4_CPtr, seL4_Word};

#[derive(Debug)]
pub struct Endpoint {
    pub cptr: seL4_CPtr,
}

impl Endpoint {
    pub fn new(cptr: seL4_CPtr) -> Self {
        Endpoint { cptr }
    }

    pub fn reply_recv_with_mrs(&self, info: libnova::ipc::MessageInfo, mrs: [u64; 4]) -> (libnova::ipc::MessageInfo, seL4_Word, [u64; 4]) {
        libnova::ipc::set_mr(0, mrs[0].try_into().unwrap());
        libnova::ipc::set_mr(1, mrs[1].try_into().unwrap());
        libnova::ipc::set_mr(2, mrs[2].try_into().unwrap());
        libnova::ipc::set_mr(3, mrs[3].try_into().unwrap());
        
        let (badge, resp_info) = libnova::ipc::reply_recv(self.cptr, info).expect("IPC ReplyRecv failed");
        
        let mr0 = libnova::ipc::get_mr(0);
        let mr1 = libnova::ipc::get_mr(1);
        let mr2 = libnova::ipc::get_mr(2);
        let mr3 = libnova::ipc::get_mr(3);
        
        (resp_info, badge, [mr0.into(), mr1.into(), mr2.into(), mr3.into()])
    }

    /// 发送消息并等待回复 (Client Side)
    /// 
    /// # Arguments
    /// * `msg` - 要发送的一个 u64 数据 (为了简化测试，只传一个字)
    /// 
    /// # Returns
    /// * `Ok(u64)` - 接收到的回复数据
    pub fn call(&self, msg: u64) -> u64 {
        let info = libnova::ipc::MessageInfo::new(
            0, // label
            0, // capsUnwrapped
            0, // extraCaps
            1, // length (1 word)
        );

        libnova::ipc::set_mr(0, msg.try_into().unwrap());
        
        if let Ok(resp_info) = libnova::ipc::call(self.cptr, info) {
             // Check length of response
            let len = resp_info.length();
            if len > 0 {
                return libnova::ipc::get_mr(0).into();
            }
        }
        0
    }

    /// 接收消息 (Server Side)
    /// 
    /// # Returns
    /// * `(u64, seL4_CPtr)` - (接收到的数据, 发送者的 reply cap)
    pub fn recv(&self) -> (u64, seL4_Word) {
        let (sender_badge, info) = libnova::ipc::recv(self.cptr);
        
        let len = info.length();
        let msg = if len > 0 { libnova::ipc::get_mr(0) } else { 0 };
        
        (msg.into(), sender_badge)
    }

    pub fn recv_with_mrs(&self) -> (libnova::ipc::MessageInfo, seL4_Word, [u64; 4]) {
        let (sender_badge, info) = libnova::ipc::recv(self.cptr);
        
        let mr0 = libnova::ipc::get_mr(0);
        let mr1 = libnova::ipc::get_mr(1);
        let mr2 = libnova::ipc::get_mr(2);
        let mr3 = libnova::ipc::get_mr(3);
        
        (info, sender_badge, [mr0.into(), mr1.into(), mr2.into(), mr3.into()])
    }



    /// 回复并等待下一个消息 (Server Loop)
    /// 
    /// # Arguments
    /// * `msg` - 回复的数据
    pub fn reply_recv(&self, msg: u64) -> (u64, seL4_Word) {
        let info = libnova::ipc::MessageInfo::new(
            0, 0, 0, 1
        );
        libnova::ipc::set_mr(0, msg.try_into().unwrap());
        
        let (sender_badge, resp_info) = libnova::ipc::reply_recv(self.cptr, info).expect("IPC ReplyRecv failed");
        
        let len = resp_info.length();
        let msg = if len > 0 { libnova::ipc::get_mr(0) } else { 0 };
        
        (msg.into(), sender_badge)
    }
}
