use base64::{
    alphabet::URL_SAFE,
    engine::{general_purpose, DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    DecodeError, Engine,
};

pub const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_encode_padding(false)
    .with_decode_padding_mode(DecodePaddingMode::RequireNone);

pub const ENGINE: GeneralPurpose = GeneralPurpose::new(&URL_SAFE, CONFIG);
