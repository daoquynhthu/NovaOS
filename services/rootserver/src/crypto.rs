use core::convert::TryInto;

pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0u32; 16];
        // Constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Key
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap());
        }
        
        // Counter
        state[12] = counter;
        
        // Nonce
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes(nonce[4*i..4*i+4].try_into().unwrap());
        }
        
        ChaCha20 { state }
    }
    
    fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = x[a].wrapping_add(x[b]); x[d] ^= x[a]; x[d] = x[d].rotate_left(16);
        x[c] = x[c].wrapping_add(x[d]); x[b] ^= x[c]; x[b] = x[b].rotate_left(12);
        x[a] = x[a].wrapping_add(x[b]); x[d] ^= x[a]; x[d] = x[d].rotate_left(8);
        x[c] = x[c].wrapping_add(x[d]); x[b] ^= x[c]; x[b] = x[b].rotate_left(7);
    }
    
    pub fn block(&self, out: &mut [u8; 64]) {
        let mut x = self.state;
        
        for _ in 0..10 {
            Self::quarter_round(&mut x, 0, 4, 8,  12);
            Self::quarter_round(&mut x, 1, 5, 9,  13);
            Self::quarter_round(&mut x, 2, 6, 10, 14);
            Self::quarter_round(&mut x, 3, 7, 11, 15);
            
            Self::quarter_round(&mut x, 0, 5, 10, 15);
            Self::quarter_round(&mut x, 1, 6, 11, 12);
            Self::quarter_round(&mut x, 2, 7, 8,  13);
            Self::quarter_round(&mut x, 3, 4, 9,  14);
        }
        
        for i in 0..16 {
            let val = x[i].wrapping_add(self.state[i]);
            let bytes = val.to_le_bytes();
            out[4*i..4*i+4].copy_from_slice(&bytes);
        }
    }
    
    #[allow(dead_code)]
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut block_bytes = [0u8; 64];
        let mut offset = 0;
        
        while offset < data.len() {
            self.block(&mut block_bytes);
            
            // XOR
            let len = core::cmp::min(64, data.len() - offset);
            for i in 0..len {
                data[offset + i] ^= block_bytes[i];
            }
            
            offset += 64;
            // Increment counter
            self.state[12] = self.state[12].wrapping_add(1);
        }
    }

    pub fn process(&mut self, data: &mut [u8], offset: usize) {
        let mut current_offset = offset;
        let mut data_idx = 0;
        
        while data_idx < data.len() {
            let block_counter = (current_offset / 64) as u32;
            let byte_in_block = current_offset % 64;
            
            // Set counter
            self.state[12] = block_counter;
            
            let mut key_block = [0u8; 64];
            self.block(&mut key_block);
            
            let len = core::cmp::min(64 - byte_in_block, data.len() - data_idx);
            for i in 0..len {
                data[data_idx + i] ^= key_block[byte_in_block + i];
            }
            
            data_idx += len;
            current_offset += len;
        }
    }
}
