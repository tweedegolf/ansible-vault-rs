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
use std::io::{BufRead, Read};
use pbkdf2::pbkdf2;
use rand::Rng;


const VAULT_1_1_PREFIX: &str = "$ANSIBLE_VAULT;1.1;AES256";
const AES_BLOCK_SIZE: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// See https://github.com/ansible/ansible/blob/devel/lib/ansible/parsing/vault/__init__.py#L1286.
fn verify_vault(key: &[u8], ciphertext: &[u8], crypted_hmac: &[u8]) -> Result<()> {
    let mut hmac = HmacSha256::new_varkey(key)?;
    hmac.update(&ciphertext);
    Ok(hmac.verify(crypted_hmac)?)
}

fn gen_init_aes_ctr(key: &str, salt: &[u8]) -> ([u8;32], [u8;32], [u8;16]) {
    let mut hmac_buffer = [0; 80];
    pbkdf2::<HmacSha256>(key.as_bytes(),salt, 10000, &mut hmac_buffer);

    let mut key1 =[0u8; 32];
    let mut key2 =[0u8; 32];
    let mut iv =[0u8; 16];
    key1.copy_from_slice(&hmac_buffer[0..32]);
    key2.copy_from_slice(&hmac_buffer[32..64]);
    iv.copy_from_slice(&hmac_buffer[64..80]);

    (key1, key2, iv)
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

    let (key1, key2, iv) = &gen_init_aes_ctr(key, salt.as_slice());

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

pub fn encrypt_vault<T:Read>(input: T, key: &str) -> Result<String> {
    let mut ciphertext = encrypt(input, key)?;
    let mut pos = 80;
    while pos < ciphertext.len() {
        ciphertext.insert(pos,'\n');
        pos = pos + 81;
    }
    let vault_text=format!{"{}\n{}", VAULT_1_1_PREFIX, ciphertext};

    Ok(vault_text)
}

pub fn encrypt<T: Read>(mut input: T, key: &str) -> Result<String> {
    // Pad input data
    let mut buffer = Vec::new();
    input.read_to_end(&mut buffer)?;
    let pos = buffer.len();
    let pad_len = AES_BLOCK_SIZE - (pos % AES_BLOCK_SIZE);
    buffer.resize(pos+pad_len, 0);
    let mut block_buffer = Pkcs7::pad(buffer.as_mut_slice(), pos, AES_BLOCK_SIZE)?;

    // Derive cryptographic keys
    let salt = rand::thread_rng().gen::<[u8; 32]>();
    let (key1, key2, iv) = &gen_init_aes_ctr(key, &salt);

    // Encrypt data
    let mut cipher = Aes256Ctr::new_var(key1, iv)?;
    cipher.apply_keystream(&mut block_buffer);

    // Message authentication
    let mut mac = HmacSha256::new_varkey(key2)?;
    mac.update(block_buffer);
    let result = mac.finalize();
    let b_hmac = result.into_bytes();

    // Format data
    let ciphertext = format!("{}\n{}\n{}",hex::encode(salt), hex::encode(b_hmac), hex::encode(block_buffer));

    Ok(hex::encode(ciphertext))
}

pub fn encrypt_vault_from_file(path: &std::path::Path, key: &str) -> Result<String> {
    let f = std::fs::File::open(path)?;
    encrypt_vault(f, key)
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

    #[test]
    fn test_encrypt() {
        let lipsum = std::fs::read_to_string("./test/lipsum.txt").unwrap();
        let encoded = crate::encrypt_vault(lipsum.as_bytes(),"shibboleet").unwrap();
        let decoded = crate::decrypt_vault(encoded.as_bytes(), "shibboleet").unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        std::assert_eq!(lipsum, decoded_str);
    }
}
