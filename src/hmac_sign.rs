use pbkdf2::hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    errors::HapiIronOxideError,
    key::{generate_key, GeneratedKey, KeyOptions},
    password::Password,
};

type HmacSha256 = Hmac<Sha256>;

/// Struct storing the HMAC digest and salt from [`hmac_with_password`] function.
pub struct HmacResult {
    /// HMAC digest.
    pub digest: Vec<u8>,
    /// HMAC salt used.
    pub salt: Option<String>,
}

/// Hashes the given data into HMAC digest.
pub fn hmac_with_password<T>(
    data: T,
    password: Password,
    options: KeyOptions,
) -> Result<HmacResult, HapiIronOxideError>
where
    T: AsRef<str>,
{
    let GeneratedKey { key, salt, iv: _ } = generate_key(password, options)?;

    let mut mac =
        HmacSha256::new_from_slice(&key.as_slice()).expect("HMAC can take key of any size");
    mac.update(data.as_ref().as_bytes());
    let result = mac.finalize();

    Ok(HmacResult {
        digest: result.into_bytes().to_vec(),
        salt,
    })
}
