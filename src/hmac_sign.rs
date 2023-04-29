use pbkdf2::hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    key::{generate_key, GeneratedKey, KeyOptions},
    password::Password,
};

type HmacSha256 = Hmac<Sha256>;

pub struct HmacResult {
    pub digest: Vec<u8>,
    pub salt: Option<String>,
}

pub fn hmac_with_password(data: String, password: Password, options: KeyOptions) -> HmacResult {
    let GeneratedKey { key, salt, iv: _ } = generate_key(password, options);

    let mut mac = HmacSha256::new_from_slice(&key.as_slice()).unwrap();
    mac.update(data.as_bytes());
    let result = mac.finalize();

    HmacResult {
        digest: result.into_bytes().to_vec(),
        salt,
    }
}
