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
use generic_array::{typenum::U32, ArrayLength};

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
pub fn encrypt<N>(
    data: String,
    password: SpecificPassword,
    options: KeyOptions,
) -> Result<EncryptedData, HapiIronOxideError>
where
    N: ArrayLength<u8>,
{
    let key = key::generate_key::<N>(password.encryption, options.clone())?;

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
    let key = key::generate_unseal_key(password.encryption, options.clone())?;

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
