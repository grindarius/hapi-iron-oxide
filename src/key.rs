use pbkdf2::pbkdf2_hmac_array;
use rand::{thread_rng, RngCore};
use sha1::Sha1;

use crate::{
    algorithm::Algorithm, constants::IV_SIZE, errors::HapiIronOxideError, password::Password,
};

/// Options to generate key.
#[derive(Clone, Debug)]
pub struct KeyOptions {
    /// Algorithm to use to generate the key.
    pub algorithm: Algorithm,
    /// How many iterations to loop through the `pbkdf2`.
    pub iterations: i32,
    /// Minimum password length.
    pub minimum_password_length: i32,
    /// Salt string to use. Will generate one if this option is [`None`]
    pub salt: Option<String>,
    /// IV to use. Will generate one if this option is [`None`]
    pub iv: Option<[u8; IV_SIZE]>,
}

#[derive(Debug)]
pub struct GeneratedKey {
    /// Returned key
    pub key: Vec<u8>,
    /// Returned salt. If there's a given salt. The salt will be used to generate the key,
    /// otherwise generate new salt.
    pub salt: Option<String>,
    pub iv: [u8; IV_SIZE],
}

/// Generates a set of key, salt, and iv that will be used for further encryption.
pub fn generate_key<const N: usize>(
    password: Password,
    options: &KeyOptions,
) -> Result<GeneratedKey, HapiIronOxideError> {
    let mut rng = thread_rng();

    // Put the iv from input into the slice if there's a given iv, otherwise generate new one.
    // The iv used in the library is always going to be 16.
    let mut iv = match options.iv {
        Some(ref given_iv) => {
            let mut iv_array: [u8; IV_SIZE] = [0; IV_SIZE];

            if given_iv.len() != IV_SIZE {
                return Err(HapiIronOxideError::InvalidIVSize);
            }

            iv_array[..given_iv.len()].copy_from_slice(given_iv.as_slice());
            iv_array
        }
        None => {
            let mut iv_array: [u8; IV_SIZE] = [0; IV_SIZE];
            rng.fill_bytes(&mut iv_array);
            iv_array
        }
    };

    match password {
        Password::String(password_string) => {
            if password_string.len() < options.minimum_password_length.try_into().unwrap() {
                return Err(HapiIronOxideError::PasswordTooShort);
            }

            let salt_string: String = options.salt.clone().unwrap_or_else(|| {
                let mut salt: [u8; N] = [0; N];
                rng.fill_bytes(&mut salt);
                hex::encode(salt)
            });

            let dk: Vec<u8> = match options.algorithm {
                Algorithm::Aes256Cbc | Algorithm::Sha256 => {
                    let key = pbkdf2_hmac_array::<Sha1, 32>(
                        password_string.as_bytes(),
                        salt_string.as_bytes(),
                        options.iterations.try_into().unwrap(),
                    );

                    key.to_vec()
                }
                Algorithm::Aes128Ctr => {
                    let key = pbkdf2_hmac_array::<Sha1, 16>(
                        password_string.as_bytes(),
                        salt_string.as_bytes(),
                        options.iterations.try_into().unwrap(),
                    );

                    key.to_vec()
                }
            };

            Ok(GeneratedKey {
                key: dk,
                salt: Some(salt_string),
                iv: match options.iv {
                    Some(ref given_iv) => {
                        iv[..given_iv.len()].copy_from_slice(&given_iv[..]);
                        iv
                    }
                    None => {
                        rng.fill_bytes(&mut iv);
                        iv
                    }
                },
            })
        }
        Password::U8(password_vector) => {
            if password_vector.len() < options.minimum_password_length.try_into().unwrap() {
                return Err(HapiIronOxideError::PasswordTooShort);
            }

            Ok(GeneratedKey {
                key: password_vector,
                salt: None,
                iv: match options.iv {
                    Some(ref given_iv) => {
                        iv[..given_iv.len()].copy_from_slice(&given_iv[..]);
                        iv
                    }
                    None => {
                        rng.fill_bytes(&mut iv);
                        iv
                    }
                },
            })
        }
    }
}

/// Generates key. Since there will always be a salt string that
/// comes in. That means the generic parameter can be of any value. Defaults as
pub fn generate_unseal_key(
    password: Password,
    options: &KeyOptions,
) -> Result<GeneratedKey, HapiIronOxideError> {
    generate_key::<32>(password, options)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECRYPTED_PASSWORD: &'static str =
        "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword";

    const DECRYPTED_MESSAGE: &'static str = "Hello World!";

    const AES256CBC_ENCRYPTED_PASSWORD: [u8; 16] = [
        0x87, 0x09, 0x6a, 0xbb, 0xec, 0x0c, 0x53, 0x01, 0x79, 0xd2, 0x74, 0x48, 0xba, 0xdb, 0x55,
        0x5f,
    ];

    const AES256CBC_GENERATED_KEY: [u8; 32] = [
        0xf3, 0x23, 0x9f, 0x37, 0x55, 0x29, 0x34, 0xdd, 0xfb, 0xb3, 0x61, 0xbe, 0xa4, 0x7a, 0xab,
        0xc7, 0x6f, 0x62, 0x1e, 0xd2, 0x49, 0x25, 0x0e, 0x1d, 0x9d, 0xf5, 0x38, 0x20, 0x4b, 0xf1,
        0x63, 0x47,
    ];

    const AES256CBC_GENERATED_SALT: &'static str =
        "b27a06366ace6bb1560ea039a5595c352a429b87f3982542da9e830a32f5468e";

    const AES256CBC_GENERATED_IV: [u8; 16] = [
        0xac, 0xc6, 0x9d, 0x62, 0x8a, 0x2b, 0x0e, 0x54, 0x55, 0x30, 0xd5, 0x82, 0xed, 0xdc, 0x49,
        0x27,
    ];

    #[test]
    fn test_success_key_output() {
        let options = KeyOptions {
            algorithm: Algorithm::Aes256Cbc,
            iterations: 2,
            minimum_password_length: 32,
            salt: Some(AES256CBC_GENERATED_SALT.to_string()),
            iv: Some(AES256CBC_GENERATED_IV),
        };

        let key =
            generate_key::<32>(Password::String(DECRYPTED_PASSWORD.to_string()), &options).unwrap();

        assert_eq!(key.salt, Some(AES256CBC_GENERATED_SALT.to_string()));
    }
}
