//! ## hapi-iron-oxide
//! This module is made to be compatible with [brc-dd/iron-webcrypto](https://github.com/brc-dd/iron-webcrypto), which is the crate that backs [vvo/iron-session](https://github.com/vvo/iron-session). This allows APIs made in Rust be able to talk to Next.js.
//!
//! ### Installation
//! ```bash
//! cargo add hapi-iron-oxide
//! ```
//!
//! ### Usage
//! ```
//! use hapi_iron_oxide::{seal, unseal};
//! use hapi_iron_oxide::typenum;
//!
//! let password = "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword";
//! let data = "Hello World Please";
//!
//! let sealed = seal::<typenum::U32, typenum::U32, _>(data.to_string(), password, Default::default()).unwrap();
//! let unsealed = unseal(sealed, password.clone(), Default::default());
//!
//! assert_eq!(unsealed.unwrap(), data.to_string());
//! ```
//!
//! ### Thank you
//! Thank you to
//! - [brc-dd/iron-webcrypto](https://github.com/brc-dd/iron-webcrypto)
//! - [iron-auth/iron-crypto](https://github.com/iron-auth/iron-crypto)
//! for the ideas and implementation details.

use base64::Engine;
use constant_time_eq::constant_time_eq;
use constants::MAC_PREFIX;
use encryption::decrypt;
use errors::HapiIronOxideError;
use generic_array::ArrayLength;
use hmac_sign::{seal_hmac_with_password, unseal_hmac_with_password};
use key::KeyOptions;
use options::SealOptions;
use password::SpecificPasswordInit;
use time::Duration;

use crate::base64_engine::ENGINE;

pub mod algorithm;
pub mod base64_engine;
pub mod constants;
pub mod encryption;
pub mod errors;
pub mod hmac_sign;
pub mod key;
pub mod options;
pub mod password;

pub use generic_array::typenum;

/// Creates sealed string from given options.
pub fn seal<E, I, U>(
    data: String,
    password: U,
    options: SealOptions,
) -> Result<String, HapiIronOxideError>
where
    E: ArrayLength<u8>,
    I: ArrayLength<u8>,
    U: SpecificPasswordInit,
{
    let normalized_password = password.normalize()?;

    let encrypted = encryption::encrypt::<E>(
        data,
        normalized_password.clone(),
        KeyOptions {
            algorithm: options.encryption.algorithm,
            iterations: options.encryption.iterations,
            minimum_password_length: options.encryption.minimum_password_length,
            salt: None,
            iv: None,
        },
    )?;

    let encrypted_base64 = ENGINE.encode(encrypted.encrypted);
    let iv_base64 = ENGINE.encode(encrypted.key.iv);

    let expiration: String = match options.ttl {
        x if x == 0 => "".to_string(),
        _ => {
            let ttl =
                time::OffsetDateTime::now_utc() + Duration::new(options.ttl.try_into().unwrap(), 0);
            let ttl_millisecond = ttl.unix_timestamp_nanos() / 1_000_000;

            ttl_millisecond.to_string()
        }
    };

    let mac_base_string = format!(
        "{}*{}*{}*{}*{}*{}",
        &MAC_PREFIX,
        normalized_password.id,
        Clone::clone(&encrypted.key.salt).unwrap_or("".to_string()),
        iv_base64,
        encrypted_base64,
        expiration
    );

    let mac_options = KeyOptions {
        algorithm: options.integrity.algorithm,
        iterations: options.integrity.iterations,
        minimum_password_length: options.integrity.minimum_password_length,
        salt: encrypted.key.salt,
        iv: None,
    };

    let result = seal_hmac_with_password::<I>(
        mac_base_string.clone(),
        Clone::clone(&normalized_password.integrity),
        mac_options,
    )?;

    let sealed = format!(
        "{}*{}*{}",
        mac_base_string,
        result.salt.unwrap_or("".to_string()),
        ENGINE.encode(result.digest)
    );

    Ok(sealed)
}

/// Unseal the sealed string back into the original string.
pub fn unseal<U>(
    sealed: String,
    password: U,
    options: SealOptions,
) -> Result<String, HapiIronOxideError>
where
    U: SpecificPasswordInit,
{
    let now = time::OffsetDateTime::now_utc() + time::Duration::new(options.local_offset.into(), 0);

    let mut parts = sealed.split("*");

    let prefix = parts.next().ok_or(HapiIronOxideError::InvalidSeal)?;
    let password_id = parts.next().ok_or(HapiIronOxideError::InvalidSeal)?;
    let encryption_salt = parts.next().ok_or(HapiIronOxideError::InvalidSeal)?;
    let encryption_iv = parts.next().ok_or(HapiIronOxideError::InvalidSeal)?;
    let encryption_value = parts.next().ok_or(HapiIronOxideError::InvalidSeal)?;
    let expiration = parts.next().ok_or(HapiIronOxideError::InvalidSeal)?;
    let hmac_salt = parts.next().ok_or(HapiIronOxideError::InvalidSeal)?;
    let hmac_digest = parts.next().ok_or(HapiIronOxideError::InvalidSeal)?;

    let mac_base_string = format!(
        "{}*{}*{}*{}*{}*{}",
        prefix, password_id, encryption_salt, encryption_iv, encryption_value, expiration
    );

    if prefix != MAC_PREFIX {
        return Err(HapiIronOxideError::InvalidSealPrefix);
    }

    if !expiration.is_empty() {
        let expiration_number = i128::from_str_radix(expiration, 10)?;
        let expiration_time =
            time::OffsetDateTime::from_unix_timestamp_nanos(expiration_number * 1_000_000)?;

        if expiration_time <= now - time::Duration::new(options.timestamp_skew.into(), 0) {
            return Err(HapiIronOxideError::ExpiredSeal);
        }
    }

    let normalized_password = password.normalize_unseal(Some(password_id))?;

    let mac_options = KeyOptions {
        algorithm: options.integrity.algorithm,
        iterations: options.integrity.iterations,
        minimum_password_length: options.integrity.minimum_password_length,
        salt: Some(hmac_salt.to_string()),
        iv: None,
    };

    let result = unseal_hmac_with_password(
        mac_base_string,
        Clone::clone(&normalized_password.integrity),
        mac_options,
    )?;

    if !constant_time_eq(
        result.digest.as_slice(),
        ENGINE.decode(hmac_digest)?.as_slice(),
    ) {
        return Err(HapiIronOxideError::InvalidHmacValue);
    }

    let decrypted_value = ENGINE.decode(encryption_value)?;
    let decrypt_options = KeyOptions {
        algorithm: options.encryption.algorithm,
        iterations: options.encryption.iterations,
        minimum_password_length: options.encryption.minimum_password_length,
        salt: Some(encryption_salt.to_string()),
        iv: Some(ENGINE.decode(encryption_iv)?),
    };

    let decrypted_vector = decrypt(decrypted_value, normalized_password, decrypt_options)?;

    Ok(String::from_utf8(decrypted_vector).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    use generic_array::typenum::{U128, U32, U64};

    const PASSWORD: &'static str =
        "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword";
    const DATA_STRING: &'static str = "{\"dis\":\"eh\"}";

    #[test]
    fn test_seal_unseal() {
        let sealed =
            seal::<U32, U32, _>(DATA_STRING.to_string(), PASSWORD, Default::default()).unwrap();
        let unsealed = unseal(sealed, PASSWORD, Default::default()).unwrap();

        assert_eq!(unsealed, DATA_STRING.to_string());
    }

    #[test]
    fn test_unseal_from_node() {
        let s = "Fe26.2**79c5378388cbe4f2c71d3ea08b562f7b26bc13c029843549bb3c155e12dc86d7*KuWCSG7MB23J8sPKmUj6Hg*AdqzRL9iLYGku3uG903Pww**a268d5bb817dc86e60e413ed25ddf833962d249c806f72019420c2a0341751a3*uh1HrJMhK4x4WhAu8pnjpNabnaDzQbCzhK31YDVsGxQ";

        let u = unseal(s.to_string(), PASSWORD, Default::default()).unwrap();

        assert_eq!(u, DATA_STRING.to_string());
    }

    #[test]
    fn test_seal_custom_salt_size() {
        let sealed =
            seal::<U64, U128, _>(DATA_STRING.to_string(), PASSWORD, Default::default()).unwrap();

        let unsealed = unseal(sealed, PASSWORD, Default::default()).unwrap();

        assert_eq!(unsealed, DATA_STRING.to_string());
    }

    #[test]
    #[should_panic]
    fn test_seal_unseal_invalid_key_size_in_vec_u8() {
        let p = b"passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword";
        let password_as_bytes = p.to_vec();

        let sealed = seal::<U32, U32, _>(
            DATA_STRING.to_string(),
            password_as_bytes.clone(),
            Default::default(),
        )
        .unwrap();
        let unsealed = unseal(sealed, password_as_bytes, Default::default()).unwrap();

        assert_eq!(unsealed, DATA_STRING.to_string());
    }
}
