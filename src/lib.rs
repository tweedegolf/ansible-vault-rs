//! Decrypting of Ansible vault 1.1 files and streams.
//!
//! This crate provides the `read_vault` function which will decrypt an
//! ansible vault and yield a byte buffer of the plaintext.
//! It detects incorrect vault secrets and incorrectly formatted vaults,
//! and yields the appropriate errors.
mod errors;

use crate::errors::*;
use aes_ctr::cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes256Ctr;
use block_padding::{Padding, Pkcs7};
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use std::io::BufRead;
use pbkdf2::pbkdf2;

const VAULT_1_1_PREFIX: &str = "$ANSIBLE_VAULT;1.1;AES256";

type HmacSha256 = Hmac<Sha256>;

/// See https://github.com/ansible/ansible/blob/devel/lib/ansible/parsing/vault/__init__.py#L1286.
fn verify_vault(key: &[u8], ciphertext: &[u8], crypted_hmac: &[u8]) -> Result<()> {
    let mut hmac = HmacSha256::new_varkey(key)?;
    hmac.update(&ciphertext);
    Ok(hmac.verify(crypted_hmac)?)
}

/// Decrypt an ansible vault stream using a key.
///
/// When succesful, yields a plaintext byte buffer.
pub fn decrypt_vault<T: std::io::Read>(input: T, key: &str) -> Result<Vec<u8>> {
    let mut lines = std::io::BufReader::new(input).lines();
    let first: String = lines
        .next()
        .ok_or_else(|| VaultError::from_kind(ErrorKind::NotAVault))??;
    let payload = lines
        .filter_map(|i| i.ok())
        .collect::<Vec<String>>()
        .join("");
    let unhex_payload = String::from_utf8(hex::decode(&payload)?)?;

    if first != VAULT_1_1_PREFIX {
        return Err(VaultError::from_kind(ErrorKind::NotAVault));
    }

    let mut lines = unhex_payload.lines();

    let salt = hex::decode(
        &lines
            .next()
            .ok_or_else(|| VaultError::from_kind(ErrorKind::InvalidFormat))?,
    )?;
    let hmac_verify = hex::decode(
        &lines
            .next()
            .ok_or_else(|| VaultError::from_kind(ErrorKind::InvalidFormat))?,
    )?;
    let mut ciphertext = hex::decode(
        &lines
            .next()
            .ok_or_else(|| VaultError::from_kind(ErrorKind::InvalidFormat))?,
    )?;

    let mut hmac_buffer = [0; 80];
    pbkdf2::<HmacSha256>(key.as_bytes(), &salt, 10000, &mut hmac_buffer);

    let key1 = &hmac_buffer[0..32];
    let key2 = &hmac_buffer[32..64];
    let iv = &hmac_buffer[64..80];

    verify_vault(key2, &ciphertext, &hmac_verify)?;

    let mut cipher = Aes256Ctr::new_var(key1, iv)
        .map_err(|_err| VaultError::from_kind(ErrorKind::InvalidFormat))?;

    cipher.apply_keystream(&mut ciphertext);
    let n = Pkcs7::unpad(&ciphertext)
        .map_err(|_| VaultError::from_kind(ErrorKind::InvalidFormat))?
        .len();
    ciphertext.truncate(n);

    Ok(ciphertext)
}

/// Decrypt an ansible vault file using a key.
///
/// When succesful, yields a plaintext byte buffer.
pub fn decrypt_vault_from_file(path: &std::path::Path, key: &str) -> Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    decrypt_vault(f, key)
}

#[cfg(test)]
mod tests {
    use crate::errors::{ErrorKind, VaultError};

    fn lipsum_path() -> std::path::PathBuf {
        use std::str::FromStr;
        std::path::PathBuf::from_str("./test/lipsum.vault").unwrap()
    }

    #[test]
    fn wrong_password() {
        let result = crate::decrypt_vault_from_file(&lipsum_path(), "not shibboleet").unwrap_err();
        std::assert_eq!(result, VaultError::from_kind(ErrorKind::IncorrectSecret));
    }

    #[test]
    fn contents() {
        let buf = crate::decrypt_vault_from_file(&lipsum_path(), "shibboleet").unwrap();
        let lipsum = std::string::String::from_utf8(buf).unwrap();
        let reference = std::fs::read_to_string("./test/lipsum.txt").unwrap();
        std::assert_eq!(lipsum, reference);
    }
}
