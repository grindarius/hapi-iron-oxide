## hapi-iron-oxide
This module is made to be compatible with [brc-dd/iron-webcrypto](https://github.com/brc-dd/iron-webcrypto), which is the crate that backs [vvo/iron-session](https://github.com/vvo/iron-session). This allows APIs made in Rust be able to talk to Next.js.

### Installation
```bash
cargo add hapi-iron-oxide
```

### Usage
```rust
use hapi_iron_oxide::seal;
use hapi_iron_oxide::typenum;

let password = "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword";
let data = "Hello World Please";

let sealed = seal::<typenum::U32, typenum::U32, _>(data.to_string(), password, Default::default());
let unsealed = unseal(sealed, password.clone(), Default::default());
```

### Thank you
Thank you to
- [brc-dd/iron-webcrypto](https://github.com/brc-dd/iron-webcrypto)
- [iron-auth/iron-crypto](https://github.com/iron-auth/iron-crypto)
for the ideas and implementation details.
