use std::collections::HashMap;

use crate::errors::HapiIronOxideError;

/// An enum that is holding the value of the password inside by its type.
///
/// The original implementation of [brc-dd/iron-webcrypto](https://github.com/brc-dd/iron-webcrypto) uses any incoming password in vector form as
/// the key directly without any salt. But when the password is in [`String`] format, we will
/// generate salt and create the key using `pbkdf2` algorithm.
#[derive(Debug, Clone)]
pub enum Password {
    U8(Vec<u8>),
    String(String),
}

/// A struct for storing a password with an ID. Uses same password for both encryption and
/// integrity.
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

/// A trait for converting a set of types to [`SpecificPassword`].
///
/// ```
/// use hapi_iron_oxide::password::{SpecificPassword, SpecificPasswordInit};
///
/// let password: [u8; 5] = [0x52, 0x6f, 0x5c, 0x42, 0xee];
/// let normalized_password: SpecificPassword = password.normalize().unwrap();
///
/// assert_eq!(normalized_password.id, "".to_string());
/// ```
pub trait SpecificPasswordInit {
    /// Normalizes the password to [`SpecificPassword`]
    ///
    /// ```
    /// use hapi_iron_oxide::password::{SpecificPassword, SpecificPasswordInit};
    ///
    /// let password: [u8; 5] = [0x52, 0x6f, 0x5c, 0x42, 0xee];
    /// let normalized_password: SpecificPassword = password.normalize().unwrap();
    ///
    /// assert_eq!(normalized_password.id, "".to_string());
    /// ```
    fn normalize(&self) -> Result<SpecificPassword, HapiIronOxideError> {
        Err(HapiIronOxideError::NormalizeUnimplemented)
    }

    /// Normalizes the password to [`SpecificPassword`], except this one takes in the optional
    /// index of the password in case the user provides the [`HashMap`] of password with an ID and
    /// the password.
    ///
    /// If the function is given a [`HashMap`], it will try to find the password using the given
    /// index, otherwise it will find the password using the `default` as key.
    fn normalize_unseal(&self, _idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        Err(HapiIronOxideError::NormalizeUnsealUnimplemented)
    }
}

impl SpecificPasswordInit for &[u8] {
    fn normalize(&self) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        Ok(SpecificPassword {
            id: "".to_string(),
            encryption: Password::U8(self.to_vec()),
            integrity: Password::U8(self.to_vec()),
        })
    }

    fn normalize_unseal(&self, _idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        Ok(SpecificPassword {
            id: "".to_string(),
            encryption: Password::U8(self.to_vec()),
            integrity: Password::U8(self.to_vec()),
        })
    }
}

impl SpecificPasswordInit for &str {
    fn normalize(&self) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        Ok(SpecificPassword {
            id: "".to_string(),
            encryption: Password::String(self.to_string()),
            integrity: Password::String(self.to_string()),
        })
    }

    fn normalize_unseal(&self, _idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        Ok(SpecificPassword {
            id: "".to_string(),
            encryption: Password::String(self.to_string()),
            integrity: Password::String(self.to_string()),
        })
    }
}

impl SpecificPasswordInit for String {
    fn normalize(&self) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        Ok(SpecificPassword {
            id: "".to_string(),
            encryption: Password::String(self.to_string()),
            integrity: Password::String(self.to_string()),
        })
    }

    fn normalize_unseal(&self, _idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        Ok(SpecificPassword {
            id: "".to_string(),
            encryption: Password::String(self.to_string()),
            integrity: Password::String(self.to_string()),
        })
    }
}

impl SpecificPasswordInit for Password {
    fn normalize(&self) -> Result<SpecificPassword, HapiIronOxideError> {
        let specific: SpecificPassword = match self {
            Password::U8(password_vector) => {
                if password_vector.is_empty() {
                    return Err(HapiIronOxideError::PasswordRequired);
                }

                SpecificPassword {
                    id: "".to_string(),
                    encryption: Clone::clone(self),
                    integrity: Clone::clone(self),
                }
            }
            Password::String(password_string) => {
                if password_string.is_empty() {
                    return Err(HapiIronOxideError::PasswordRequired);
                }

                SpecificPassword {
                    id: "".to_string(),
                    encryption: Clone::clone(self),
                    integrity: Clone::clone(self),
                }
            }
        };

        Ok(specific)
    }

    fn normalize_unseal(&self, _idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        Ok(SpecificPassword {
            id: "".to_string(),
            encryption: Clone::clone(self),
            integrity: Clone::clone(self),
        })
    }
}

impl SpecificPasswordInit for SecretPassword {
    fn normalize(&self) -> Result<SpecificPassword, HapiIronOxideError> {
        Ok(SpecificPassword {
            id: self.id.clone(),
            encryption: self.secret.clone(),
            integrity: self.secret.clone(),
        })
    }

    fn normalize_unseal(&self, _idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        Ok(SpecificPassword {
            id: self.id.clone(),
            encryption: self.secret.clone(),
            integrity: self.secret.clone(),
        })
    }
}

impl SpecificPasswordInit for SpecificPassword {
    fn normalize(&self) -> Result<SpecificPassword, HapiIronOxideError> {
        Ok(Clone::clone(self))
    }

    fn normalize_unseal(&self, _idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        Ok(Clone::clone(self))
    }
}

impl SpecificPasswordInit for HashMap<String, &[u8]> {
    fn normalize_unseal(&self, idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        if let Some(password_idx) = idx {
            match self.get(password_idx) {
                Some(p) => p.normalize(),
                None => Err(HapiIronOxideError::PasswordRequired),
            }
        } else {
            match self.get("default") {
                Some(p) => p.normalize(),
                None => Err(HapiIronOxideError::PasswordRequired),
            }
        }
    }
}

impl SpecificPasswordInit for HashMap<String, String> {
    fn normalize_unseal(&self, idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        if let Some(password_idx) = idx {
            match self.get(password_idx) {
                Some(p) => p.normalize(),
                None => Err(HapiIronOxideError::PasswordRequired),
            }
        } else {
            match self.get("default") {
                Some(p) => p.normalize(),
                None => Err(HapiIronOxideError::PasswordRequired),
            }
        }
    }
}

impl SpecificPasswordInit for HashMap<String, Password> {
    fn normalize_unseal(&self, idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        if let Some(password_idx) = idx {
            match self.get(password_idx) {
                Some(p) => p.normalize(),
                None => Err(HapiIronOxideError::PasswordRequired),
            }
        } else {
            match self.get("default") {
                Some(p) => p.normalize(),
                None => Err(HapiIronOxideError::PasswordRequired),
            }
        }
    }
}

impl SpecificPasswordInit for HashMap<String, SecretPassword> {
    fn normalize_unseal(&self, idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        if let Some(password_idx) = idx {
            match self.get(password_idx) {
                Some(p) => p.normalize(),
                None => Err(HapiIronOxideError::PasswordRequired),
            }
        } else {
            match self.get("default") {
                Some(p) => p.normalize(),
                None => Err(HapiIronOxideError::PasswordRequired),
            }
        }
    }
}

impl SpecificPasswordInit for HashMap<String, SpecificPassword> {
    fn normalize_unseal(&self, idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        if self.is_empty() {
            return Err(HapiIronOxideError::PasswordRequired);
        }

        if let Some(password_idx) = idx {
            match self.get(password_idx) {
                Some(p) => Ok(Clone::clone(p)),
                None => Err(HapiIronOxideError::PasswordRequired),
            }
        } else {
            match self.get("default") {
                Some(p) => Ok(Clone::clone(p)),
                None => Err(HapiIronOxideError::PasswordRequired),
            }
        }
    }
}

impl<const N: usize> SpecificPasswordInit for [u8; N] {
    fn normalize(&self) -> Result<SpecificPassword, HapiIronOxideError> {
        Ok(SpecificPassword {
            id: "".to_string(),
            encryption: Password::U8(self.to_vec()),
            integrity: Password::U8(self.to_vec()),
        })
    }

    fn normalize_unseal(&self, _idx: Option<&str>) -> Result<SpecificPassword, HapiIronOxideError> {
        Ok(SpecificPassword {
            id: "".to_string(),
            encryption: Password::U8(self.to_vec()),
            integrity: Password::U8(self.to_vec()),
        })
    }
}
