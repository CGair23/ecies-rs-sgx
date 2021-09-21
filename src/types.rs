use crate::consts::CMAC_LENGTH;

pub type CMac = [u8; CMAC_LENGTH];

/// Type alias for `[u8; 32]`, which is a 256-bit key
pub type AesKey = [u8; 32];