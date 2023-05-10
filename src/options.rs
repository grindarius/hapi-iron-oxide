use crate::algorithm::Algorithm;

#[derive(Debug, PartialEq)]
pub struct EncryptionOptions {
    pub algorithm: Algorithm,
    pub iterations: i32,
    pub minimum_password_length: i32,
}

#[derive(Debug, PartialEq)]
pub struct SealOptions {
    pub encryption: EncryptionOptions,
    pub integrity: EncryptionOptions,
    pub ttl: i64,
    pub timestamp_skew: u32,
    pub local_offset: i32,
}

pub struct SealOptionsBuilder {
    encryption: EncryptionOptions,
    integrity: EncryptionOptions,
    ttl: i64,
    timestamp_skew: u32,
    local_offset: i32,
}

impl Default for SealOptionsBuilder {
    fn default() -> Self {
        Self {
            encryption: EncryptionOptions {
                algorithm: Algorithm::Aes256Cbc,
                iterations: 1,
                minimum_password_length: 32,
            },
            integrity: EncryptionOptions {
                algorithm: Algorithm::Sha256,
                iterations: 1,
                minimum_password_length: 32,
            },
            ttl: 0,
            timestamp_skew: 60,
            local_offset: 0,
        }
    }
}

impl Default for SealOptions {
    fn default() -> Self {
        Self {
            encryption: EncryptionOptions {
                algorithm: Algorithm::Aes256Cbc,
                iterations: 1,
                minimum_password_length: 32,
            },
            integrity: EncryptionOptions {
                algorithm: Algorithm::Sha256,
                iterations: 1,
                minimum_password_length: 32,
            },
            ttl: 0,
            timestamp_skew: 60,
            local_offset: 0,
        }
    }
}

impl SealOptions {
    pub fn config(&self) -> &Self {
        self
    }
}

impl SealOptionsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encryption(mut self, e: EncryptionOptions) -> Self {
        self.encryption = e;
        self
    }

    pub fn integrity(mut self, i: EncryptionOptions) -> Self {
        self.integrity = i;
        self
    }

    pub fn ttl(mut self, ttl: i64) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn timestamp_skew(mut self, timestamp_skew: u32) -> Self {
        self.timestamp_skew = timestamp_skew;
        self
    }

    pub fn local_offset(mut self, local_offset: i32) -> Self {
        self.local_offset = local_offset;
        self
    }

    pub fn finish(self) -> SealOptions {
        SealOptions {
            encryption: self.encryption,
            integrity: self.integrity,
            ttl: self.ttl,
            timestamp_skew: self.timestamp_skew,
            local_offset: self.local_offset,
        }
    }
}
