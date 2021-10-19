# ansible-vault

```toml
[dependencies]
ansible-vault = "0.2.1"
```

Encrypt and decrypt Ansible Vault files

This library provides methods to encrypt and decrypt ansible vault data, in 1.1 format
It exposes six methods:
* encrypt : Encrypt the input to a string without header `$ANSIBLE_VAULT;1.1;AES256` nor indentation,
* encrypt_vault : Encrypt the input, and format like ansible (with header and indentation),
* encrypt_vault_from_file : Encrypt the given file (wrapper for `encrypt_vault`)
* decrypt : Decrypt a message string without header nor indentation
* decrypt_vault : Decrypt a vault intput (with header and optionally indentation)
* decrypt_vault_from file : Decrypt an ansible vault from file (wrapper for `decrypt_vault`)

### Usage
Simple usage

```rust
use ansible_vault::{encrypt_vault, decrypt_vault};
let lipsum = "Lorem ipsum dolor…";
let encoded = encrypt_vault(lipsum.as_bytes(),"5Up€rs3creT").unwrap();
let decoded = decrypt_vault(encoded.as_bytes(), "5Up€rs3creT").unwrap();
let decoded_str = String::from_utf8(decoded).unwrap();
assert_eq!(lipsum, decoded_str);
```

License: MIT
