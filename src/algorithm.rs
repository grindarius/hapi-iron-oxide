#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    Aes128Ctr,
    Aes256Cbc,
    Sha256,
}

impl Algorithm {
    pub fn name(self: &Self) -> String {
        match self {
            &Self::Aes256Cbc => "AES-CBC".to_owned(),
            &Self::Aes128Ctr => "AES-CTR".to_owned(),
            &Self::Sha256 => "SHA-256".to_owned(),
        }
    }

    pub fn key_bits(self: &Self) -> i32 {
        match self {
            &Self::Aes256Cbc | &Self::Sha256 => 256,
            &Self::Aes128Ctr => 128,
        }
    }

    pub fn iv_bits(self: &Self) -> i32 {
        match self {
            &Self::Aes256Cbc | &Self::Aes128Ctr => 128,
            &Self::Sha256 => 0,
        }
    }
}
