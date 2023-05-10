#[derive(Clone, Copy, Debug, PartialEq)]
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

    pub const fn key_bits(self: &Self) -> usize {
        match self {
            &Self::Aes256Cbc => 32,
            &Self::Aes128Ctr => 16,
            &Self::Sha256 => 32,
        }
    }
}
