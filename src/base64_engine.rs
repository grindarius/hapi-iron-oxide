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
}
