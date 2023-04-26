use crate::{
    algorithm::Algorithm,
    key::{self, GeneratedKey, KeyOptions},
    password::SpecificPassword,
};
use aes::{
    cipher::{BlockDecryptMut, StreamCipher},
    Aes128, Aes256,
};
use cbc::cipher::block_padding::Pkcs7;
use ctr::cipher::{BlockEncryptMut, KeyIvInit};

pub struct EncryptedData {
    pub encrypted: Vec<u8>,
    pub key: GeneratedKey,
}

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

type Aes128Ctr = ctr::Ctr64LE<Aes128>;

pub fn encrypt(data: String, password: SpecificPassword, options: KeyOptions) -> EncryptedData {
    let key = key::generate_key(password.encryption, options.clone());

    let encrypted_data = match options.algorithm {
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
        _ => {
            panic!("invalid encrytion algorithm");
        }
    };

    EncryptedData {
        key,
        encrypted: encrypted_data,
    }
}

pub fn decrypt(data: Vec<u8>, password: SpecificPassword, options: KeyOptions) -> Vec<u8> {
    let key = key::generate_key(password.encryption, options.clone());

    let decrypted_data = match options.algorithm {
        Algorithm::Aes256Cbc => {
            let plaintext = Aes256CbcDec::new(key.key.as_slice().into(), &key.iv.into())
                .decrypt_padded_vec_mut::<Pkcs7>(&data)
                .unwrap();

            plaintext
        }
        Algorithm::Aes128Ctr => {
            let mut buf: Vec<u8> = Vec::from_iter(data.iter().cloned());

            let mut cipher = Aes128Ctr::new(key.key.as_slice().into(), &key.iv.into());

            for chunk in buf.chunks_mut(3) {
                cipher.apply_keystream(chunk);
            }

            buf
        }
        _ => {
            panic!("invalid decryption algorithm");
        }
    };

    decrypted_data
}
