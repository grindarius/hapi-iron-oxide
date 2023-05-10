use pbkdf2::hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    algorithm::Algorithm,
    errors::HapiIronOxideError,
    key::{generate_key, generate_unseal_key, GeneratedKey, KeyOptions},
    password::Password,
};

type HmacSha256 = Hmac<Sha256>;

/// Struct storing the HMAC digest and salt.
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
pub fn seal_hmac_with_password<const N: usize>(
    data: String,
    password: Password,
    options: KeyOptions,
) -> Result<HmacResult, HapiIronOxideError> {
    let GeneratedKey { key, salt, iv: _ } = generate_key::<N>(password, &options)?;

    match options.algorithm {
        Algorithm::Sha256 => {
            let result = hmac_with_password(data, key, salt);
            return Ok(result);
        }
        what => return Err(HapiIronOxideError::InvalidHashAlgorithm(what.name())),
    }
}

pub fn unseal_hmac_with_password(
    data: String,
    password: Password,
    options: KeyOptions,
) -> Result<HmacResult, HapiIronOxideError> {
    let GeneratedKey { key, salt, iv: _ } = generate_unseal_key(password, &options)?;

    match options.algorithm {
        Algorithm::Sha256 => {
            let result = hmac_with_password(data, key, salt);
            return Ok(result);
        }
        what => return Err(HapiIronOxideError::InvalidHashAlgorithm(what.name())),
    }
}
