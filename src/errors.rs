use thiserror::Error;

#[derive(Error, Debug)]
pub enum HapiIronOxideError {
    #[error("password field is empty")]
    PasswordFieldEmpty,
    #[error("password required")]
    PasswordRequired,
    #[error("password hashmap is empty")]
    HashMapEmpty,
    #[error("function \"normalize\" is not implemented")]
    NormalizeUnimplemented,
}
