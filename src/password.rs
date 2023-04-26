/// An enum that is holding the value of the password inside.
///
/// The original implementation of `iron-webcrypto` uses any incoming password in vector form as
/// the key directly without any salt. But when the password is in [`String`] format, we will
/// generate salt and create the key using `pbkdf2` algorithm.
#[derive(Debug, Clone)]
pub enum Password {
    U8(Vec<u8>),
    String(String),
}

/// A struct for storing a password with an ID.
#[derive(Clone)]
pub struct SecretPassword {
    /// The ID of the password.
    pub id: String,
    /// The password.
    pub secret: Password,
}

/// A password with an ID, encryption, and integrity password.
#[derive(Clone)]
pub struct SpecificPassword {
    /// The ID of the password
    pub id: String,
    /// The password used for encryption.
    pub encryption: Password,
    /// The password used for integrity.
    pub integrity: Password,
}

pub trait SpecificPasswordInit {
    fn normalize(&self) -> SpecificPassword;
}

impl SpecificPasswordInit for &[u8] {
    fn normalize(&self) -> SpecificPassword {
        SpecificPassword {
            id: "".to_string(),
            encryption: Password::U8(self.to_vec()),
            integrity: Password::U8(self.to_vec()),
        }
    }
}

impl SpecificPasswordInit for &str {
    fn normalize(&self) -> SpecificPassword {
        SpecificPassword {
            id: "".to_string(),
            encryption: Password::String(self.to_string()),
            integrity: Password::String(self.to_string()),
        }
    }
}

impl SpecificPasswordInit for Password {
    fn normalize(&self) -> SpecificPassword {
        SpecificPassword {
            id: "".to_string(),
            encryption: Clone::clone(self),
            integrity: Clone::clone(self),
        }
    }
}

impl SpecificPasswordInit for SecretPassword {
    fn normalize(&self) -> SpecificPassword {
        SpecificPassword {
            id: self.id.clone(),
            encryption: self.secret.clone(),
            integrity: self.secret.clone(),
        }
    }
}

impl SpecificPasswordInit for SpecificPassword {
    fn normalize(&self) -> SpecificPassword {
        Clone::clone(self)
    }
}
