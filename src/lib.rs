use base64::Engine;
use constant_time_eq::constant_time_eq;
use constants::MAC_PREFIX;
use encryption::decrypt;
use hmac_sign::hmac_with_password;
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

fn seal<U>(data: String, password: U, options: SealOptions) -> String
where
    U: SpecificPasswordInit,
{
    let normalized_password = password.normalize();

    let encrypted = encryption::encrypt(
        data,
        normalized_password.clone(),
        KeyOptions {
            algorithm: options.encryption.algorithm,
            iterations: options.encryption.iterations,
            minimum_password_length: options.encryption.minimum_password_length,
            salt: None,
            iv: None,
        },
    );

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

    let result = hmac_with_password(
        mac_base_string.clone(),
        Clone::clone(&normalized_password.integrity),
        mac_options,
    );

    let sealed = format!(
        "{}*{}*{}",
        mac_base_string,
        result.salt.unwrap_or("".to_string()),
        ENGINE.encode(result.digest)
    );

    sealed
}

/// Unseal the sealed string back into the original string
pub fn unseal<U>(sealed: String, password: U, options: SealOptions) -> String
where
    U: SpecificPasswordInit,
{
    let now = time::OffsetDateTime::now_utc() + time::Duration::new(options.local_offset.into(), 0);

    let mut parts = sealed.split("*");

    let prefix = parts.next().unwrap();
    let password_id = parts.next().unwrap();
    let encryption_salt = parts.next().unwrap();
    let encryption_iv = parts.next().unwrap();
    let encryption_value = parts.next().unwrap();
    let expiration = parts.next().unwrap();
    let hmac_salt = parts.next().unwrap();
    let hmac_digest = parts.next().expect("wrong format");

    let mac_base_string = format!(
        "{}*{}*{}*{}*{}*{}",
        prefix, password_id, encryption_salt, encryption_iv, encryption_value, expiration
    );

    if prefix != MAC_PREFIX {
        panic!("wrong mac prefix");
    }

    if !expiration.is_empty() {
        let expiration = match expiration.parse::<i128>() {
            Ok(e) => time::OffsetDateTime::from_unix_timestamp_nanos(e * 1_000_000).unwrap(),
            Err(e) => panic!("{}", e),
        };

        if expiration <= now - time::Duration::new(options.timestamp_skew.into(), 0) {
            panic!("expired seal");
        }
    }

    let normalized_password = password.normalize();

    let mac_options = KeyOptions {
        algorithm: options.integrity.algorithm,
        iterations: options.integrity.iterations,
        minimum_password_length: options.integrity.minimum_password_length,
        salt: Some(hmac_salt.to_string()),
        iv: None,
    };

    let result = hmac_with_password(
        mac_base_string,
        Clone::clone(&normalized_password.integrity),
        mac_options,
    );

    if !constant_time_eq(
        result.digest.as_slice(),
        ENGINE.decode(hmac_digest).unwrap().as_slice(),
    ) {
        panic!("bad hmac value");
    }

    let decrypted_value = ENGINE.decode(encryption_value).unwrap();
    let decrypt_options = KeyOptions {
        algorithm: options.encryption.algorithm,
        iterations: options.encryption.iterations,
        minimum_password_length: options.encryption.minimum_password_length,
        salt: Some(encryption_salt.to_string()),
        iv: Some(ENGINE.decode(encryption_iv).unwrap()),
    };

    let decrypted_vector = decrypt(decrypted_value, normalized_password, decrypt_options);

    String::from_utf8(decrypted_vector).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &'static str =
        "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword";
    const DATA_STRING: &'static str = "{\"dis\":\"eh\"}";

    #[test]
    fn test_seal_unseal() {
        let sealed = seal(DATA_STRING.to_string(), PASSWORD, Default::default());
        let unsealed = unseal(sealed, PASSWORD, Default::default());

        assert_eq!(unsealed, DATA_STRING);
    }

    #[test]
    fn test_unseal_from_node() {
        let s = "Fe26.2**79c5378388cbe4f2c71d3ea08b562f7b26bc13c029843549bb3c155e12dc86d7*KuWCSG7MB23J8sPKmUj6Hg*AdqzRL9iLYGku3uG903Pww**a268d5bb817dc86e60e413ed25ddf833962d249c806f72019420c2a0341751a3*uh1HrJMhK4x4WhAu8pnjpNabnaDzQbCzhK31YDVsGxQ";

        let u = unseal(s.to_string(), PASSWORD, Default::default());

        assert_eq!(u, "{\"dis\":\"eh\"}".to_string());
    }
}
