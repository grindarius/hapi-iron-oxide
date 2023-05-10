## hapi-iron-oxide
This module is made to be compatible with [brc-dd/iron-webcrypto](https://github.com/brc-dd/iron-webcrypto), which is the crate that backs [vvo/iron-session](https://github.com/vvo/iron-session). This allows APIs made in Rust be able to talk to Next.js.

### Installation
```bash
cargo add hapi-iron-oxide
```

### Usage
Salt size can be customized from both const generics. The first generic argument is the salt size of the encryption algorithm (AES-256, AES-128). And the second generic argument is the salt size of integrity algorithm (SHA-256).
```rust
use hapi_iron_oxide::*;

let password = "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword";
let data = "Hello World Please";

let sealed = seal::<32, 32, _>(data.to_string(), password, Default::default());
let unsealed = unseal(sealed, password.clone(), Default::default());

assert_eq!(unsealed.unwrap(), data.to_string());
```

The options struct can be customized like This
```rust
use hapi_iron_oxide::*;

let password = "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword";
let data = "Hello World Please";

let options = SealOptionsBuilder::new().ttl(1000);

let sealed = seal::<32, 32, _>(data.to_string(), password, options);

assert_eq!(
    options,
    SealOptions {
        encryption: EncryptionOptions {
            algorithm: Algorithm::Aes256Cbc,
            iterations: 1,
            minimum_password_length: 32,
        },
        integrity: EncryptionOptions {
            algorithm: Algorithm::Sha256,
            iterations: 1,
            minimum_password_length: 32,
        },
        ttl: 1000,
        timestamp_skew: 60,
        local_offset: 0,
    }
);
assert!(!sealed.is_empty());
```

### Thank you
Thank you to
- [brc-dd/iron-webcrypto](https://github.com/brc-dd/iron-webcrypto)
- [iron-auth/iron-crypto](https://github.com/iron-auth/iron-crypto)
for the ideas and implementation details.
