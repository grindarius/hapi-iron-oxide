use generic_array::{typenum::U32, ArrayLength};
use pbkdf2::hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    errors::HapiIronOxideError,
    key::{generate_key, generate_unseal_key, GeneratedKey, KeyOptions},
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

fn hmac_with_password(data: String, key: Vec<u8>, salt: Option<String>) -> HmacResult {
    let mut mac =
        HmacSha256::new_from_slice(&key.as_slice()).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let result = mac.finalize();

    HmacResult {
        digest: result.into_bytes().to_vec(),
        salt,
    }
}

/// Hashes the given data into HMAC digest.
pub fn seal_hmac_with_password<N>(
    data: String,
    password: Password,
    options: KeyOptions,
) -> Result<HmacResult, HapiIronOxideError>
where
    N: ArrayLength<u8>,
{
    let GeneratedKey { key, salt, iv: _ } = generate_key::<N>(password, options)?;
    let result = hmac_with_password(data, key, salt);
    Ok(result)
}

pub fn unseal_hmac_with_password(
    data: String,
    password: Password,
    options: KeyOptions,
) -> Result<HmacResult, HapiIronOxideError> {
    let GeneratedKey { key, salt, iv: _ } = generate_unseal_key(password, options)?;
    let result = hmac_with_password(data, key, salt);
    Ok(result)
}
