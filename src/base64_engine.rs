use base64::{
    alphabet::URL_SAFE,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};

pub const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_encode_padding(false)
    .with_decode_padding_mode(DecodePaddingMode::RequireNone);

pub const ENGINE: GeneralPurpose = GeneralPurpose::new(&URL_SAFE, CONFIG);

#[cfg(test)]
mod tests {
    use crate::constants::IV_SIZE;

    use super::*;
    use base64::Engine;

    const RAW_STRING: &'static str = "Hello World! Hello World!";
    const ENCODED_STRING: &'static str = "SGVsbG8gV29ybGQhIEhlbGxvIFdvcmxkIQ";

    #[test]
    fn test_encode_to_base64() {
        assert_eq!(ENCODED_STRING, ENGINE.encode(RAW_STRING));
    }

    #[test]
    fn test_decode_to_raw_string() {
        let encoded = ENGINE.encode(RAW_STRING);

        assert_eq!(ENGINE.decode(encoded), Ok(RAW_STRING.as_bytes().to_vec()));
    }

    #[test]
    fn test_decode_to_slice() {
        let bytes: [u8; IV_SIZE] = [
            0, 92, 205, 55, 38, 231, 112, 41, 89, 134, 157, 210, 174, 104, 194, 121,
        ];

        let encoded = ENGINE.encode(bytes);

        assert_eq!("AFzNNybncClZhp3SrmjCeQ", encoded.as_str());

        let mut encoded_bytes: [u8; IV_SIZE] = [0; IV_SIZE];
        ENGINE
            .decode_slice_unchecked(encoded, &mut encoded_bytes)
            .unwrap();

        assert_eq!(bytes, encoded_bytes);
    }
}
