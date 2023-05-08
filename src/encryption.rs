use crate::{
    algorithm::Algorithm,
    errors::HapiIronOxideError,
    key::{self, GeneratedKey, KeyOptions},
    password::SpecificPassword,
};
use aes::{
    cipher::{BlockDecryptMut, StreamCipher},
    Aes128, Aes256,
};
use cbc::cipher::block_padding::Pkcs7;
use ctr::cipher::{BlockEncryptMut, KeyIvInit};

/// Struct storing the encrypted data from the [`encrypt`] function.
pub struct EncryptedData {
    /// Encrypted vector.
    pub encrypted: Vec<u8>,
    /// Key used to encrypt the data.
    pub key: GeneratedKey,
}

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

type Aes128Ctr = ctr::Ctr64LE<Aes128>;

/// Encrypts the given data into ciphered text string.
pub fn encrypt<const N: usize>(
    data: String,
    password: SpecificPassword,
    options: KeyOptions,
) -> Result<EncryptedData, HapiIronOxideError> {
    let key = key::generate_key::<N>(password.encryption, &options)?;

    let encrypted_data: Vec<u8> = match options.algorithm {
        Algorithm::Aes256Cbc => {
            let ciphered_text = Aes256CbcEnc::new(key.key.as_slice().into(), &key.iv.into())
                .encrypt_padded_vec_mut::<Pkcs7>(data.as_bytes());

            ciphered_text
        }
        Algorithm::Aes128Ctr => {
            let mut buf: Vec<u8> = data.as_bytes().to_vec();

            let mut cipher = Aes128Ctr::new(key.key.as_slice().into(), &key.iv.into());
            cipher.apply_keystream(&mut buf);

            buf
        }
        what => return Err(HapiIronOxideError::InvalidEncryptionAlgorithm(what.name())),
    };

    Ok(EncryptedData {
        key,
        encrypted: encrypted_data,
    })
}

/// Decrypts the ciphered bytes to plaintext bytes.
pub fn decrypt(
    data: Vec<u8>,
    password: SpecificPassword,
    options: KeyOptions,
) -> Result<Vec<u8>, HapiIronOxideError> {
    let key = key::generate_unseal_key(password.encryption, &options)?;

    let decrypted_data = match options.algorithm {
        Algorithm::Aes256Cbc => {
            let plaintext = Aes256CbcDec::new(key.key.as_slice().into(), &key.iv.into())
                .decrypt_padded_vec_mut::<Pkcs7>(&data)
                .map_err(|_| HapiIronOxideError::UnpadError)?;

            plaintext
        }
        Algorithm::Aes128Ctr => {
            let mut plaintext_buf: Vec<u8> = Vec::from_iter(data.iter().cloned());
            let mut cipher = Aes128Ctr::new(key.key.as_slice().into(), &key.iv.into());

            for chunk in plaintext_buf.chunks_mut(3) {
                cipher.apply_keystream(chunk);
            }

            plaintext_buf
        }
        what => return Err(HapiIronOxideError::InvalidDecryptionAlgorithm(what.name())),
    };

    Ok(decrypted_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{errors::HapiIronOxideError, password::SpecificPasswordInit};

    const DECRYPTED_PASSWORD: &'static str =
        "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword";

    const DECRYPTED_MESSAGE: &'static str = "Hello World!";

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

    const AES128CTR_GENERATED_KEY: [u8; 16] = [
        0xf3, 0x23, 0x9f, 0x37, 0x55, 0x29, 0x34, 0xdd, 0xfb, 0xb3, 0x61, 0xbe, 0xa4, 0x7a, 0xab,
        0xc7,
    ];

    const AES128CTR_GENERATED_SALT: &'static str =
        "b27a06366ace6bb1560ea039a5595c352a429b87f3982542da9e830a32f5468e";

    const AES128CTR_GENERATED_IV: [u8; 16] = [
        0xac, 0xc6, 0x9d, 0x62, 0x8a, 0x2b, 0x0e, 0x54, 0x55, 0x30, 0xd5, 0x82, 0xed, 0xdc, 0x49,
        0x27,
    ];

    #[test]
    fn test_aes_256_cbc_encrypt() {
        let options = KeyOptions {
            algorithm: Algorithm::Aes256Cbc,
            iterations: 2,
            minimum_password_length: 32,
            salt: Some(AES256CBC_GENERATED_SALT.to_string()),
            iv: Some(AES256CBC_GENERATED_IV),
        };

        let data = encrypt::<32>(
            DECRYPTED_MESSAGE.to_string(),
            DECRYPTED_PASSWORD.to_string().normalize().unwrap(),
            options,
        );

        assert_eq!(data.is_ok(), true);

        let data = data.unwrap();

        assert_eq!(data.key.key, AES256CBC_GENERATED_KEY.to_vec());
        assert_eq!(data.key.salt.unwrap(), AES256CBC_GENERATED_SALT.to_string());
        assert_eq!(data.key.iv, AES256CBC_GENERATED_IV);
    }

    #[test]
    fn test_aes_128_ctr_encrypted() {
        let options = KeyOptions {
            algorithm: Algorithm::Aes128Ctr,
            iterations: 2,
            minimum_password_length: 32,
            salt: Some(AES128CTR_GENERATED_SALT.to_string()),
            iv: Some(AES128CTR_GENERATED_IV),
        };

        let data = encrypt::<32>(
            DECRYPTED_MESSAGE.to_string(),
            DECRYPTED_PASSWORD.to_string().normalize().unwrap(),
            options,
        );

        assert_eq!(data.is_ok(), true);

        let data = data.unwrap();

        assert_eq!(data.key.key, AES128CTR_GENERATED_KEY.to_vec());
        assert_eq!(data.key.salt.unwrap(), AES128CTR_GENERATED_SALT.to_string());
        assert_eq!(data.key.iv, AES128CTR_GENERATED_IV);
    }

    #[test]
    fn test_sha_256_encrypt_returns_error() {
        let options = KeyOptions {
            algorithm: Algorithm::Sha256,
            iterations: 2,
            minimum_password_length: 32,
            salt: None,
            iv: None,
        };

        let data = encrypt::<32>(
            DECRYPTED_MESSAGE.to_string(),
            DECRYPTED_PASSWORD.to_string().normalize().unwrap(),
            options,
        );

        assert_eq!(
            data.err(),
            Some(HapiIronOxideError::InvalidEncryptionAlgorithm(
                "SHA-256".to_string()
            ))
        );
    }
}
