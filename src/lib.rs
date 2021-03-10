//! Encrypt and decrypt Ansible Vault files
//!
//! This library provides methods to encrypt and decrypt ansible vault data, in 1.1 format
//! It exposes six methods:
//! * encrypt : Encrypt the input to a string without header `$ANSIBLE_VAULT;1.1;AES256` nor indentation,
//! * encrypt_vault : Encrypt the input, and format like ansible (with header and indentation),
//! * encrypt_vault_from_file : Encrypt the given file (wrapper for `encrypt_vault`)
//! * decrypt : Decrypt a message string without header nor indentation
//! * decrypt_vault : Decrypt a vault intput (with header and optionally indentation)
//! * decrypt_vault_from file : Decrypt an ansible vault from file (wrapper for `decrypt_vault`)
//!
//! ## Usage
//! Simple usage
//!
//! ```rust
//! use ansible_vault::{encrypt_vault, decrypt_vault};
//! let lipsum = "Lorem ipsum dolor…";
//! let encoded = encrypt_vault(lipsum.as_bytes(),"5Up€rs3creT").unwrap();
//! let decoded = decrypt_vault(encoded.as_bytes(), "5Up€rs3creT").unwrap();
//! let decoded_str = String::from_utf8(decoded).unwrap();
//! assert_eq!(lipsum, decoded_str);
//! ```
mod errors;

pub use crate::errors::VaultError;
use crate::errors::*;
use aes_ctr::cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes256Ctr;
use block_padding::{Padding, Pkcs7};
use hmac::{Hmac, Mac, NewMac};
use pbkdf2::pbkdf2;
use rand::Rng;
use sha2::Sha256;
use std::fs::File;
use std::io::{BufRead, Read};
use std::path::Path;

const VAULT_1_1_PREFIX: &str = "$ANSIBLE_VAULT;1.1;AES256";
const AES_BLOCK_SIZE: usize = 16; // size in bytes
const KEY_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Verify vault data with derived key2 and hmac authentication
fn verify_vault(key: &[u8], ciphertext: &[u8], crypted_hmac: &[u8]) -> Result<()> {
    let mut hmac = HmacSha256::new_varkey(key)?;
    hmac.update(&ciphertext);
    Ok(hmac.verify(crypted_hmac)?)
}

/// Generate derived keys and initialization vector from given key and salt
fn generate_derived_key(
    key: &str,
    salt: &[u8],
) -> ([u8; KEY_SIZE], [u8; KEY_SIZE], [u8; AES_BLOCK_SIZE]) {
    let mut hmac_buffer = [0; 2 * KEY_SIZE + AES_BLOCK_SIZE];
    pbkdf2::<HmacSha256>(key.as_bytes(), salt, 10000, &mut hmac_buffer);

    let mut key1 = [0u8; KEY_SIZE];
    let mut key2 = [0u8; KEY_SIZE];
    let mut iv = [0u8; AES_BLOCK_SIZE];
    key1.copy_from_slice(&hmac_buffer[0..KEY_SIZE]);
    key2.copy_from_slice(&hmac_buffer[KEY_SIZE..2 * KEY_SIZE]);
    iv.copy_from_slice(&hmac_buffer[2 * KEY_SIZE..2 * KEY_SIZE + AES_BLOCK_SIZE]);

    (key1, key2, iv)
}

/// Decrypt ansible-vault payload (without header, no indentation nor carriage returns)
///
/// # Arguments
/// * `input` : a data reader (&[u8], file, etc…) to the vault payload
/// * `key` : the key to use decrypt
///
/// # Example
/// ```rust, no_run
///  # use ansible_vault::decrypt;
///  let lipsum = "33666638363066623664653234386231616339646438303933633830376132633330353032393364\
///                3363373531316565663539326661393165323030383934380a366133633066623963303665303238\
///                34633364626339313035633763313034366538363537306265316532663531363632383333353737\
///                3863616362363731660a666161623033666331663937626433313432616266393830376431393665\
///                3965";
///  let decoded = decrypt(lipsum.as_bytes(),"hush").unwrap();
///  let decoded_str = String::from_utf8(decoded).unwrap();
///  assert_eq!("lipsum", decoded_str);
/// ```
pub fn decrypt<T: Read>(mut input: T, key: &str) -> Result<Vec<u8>> {
    // read payload
    let mut payload = String::new();
    input.read_to_string(&mut payload)?;
    let unhex_payload = String::from_utf8(hex::decode(&payload)?)?;

    // extract salt, hmac and crypted data
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

    // check data integrity
    let (key1, key2, iv) = &generate_derived_key(key, salt.as_slice());
    verify_vault(key2, &ciphertext, &hmac_verify)?;

    // decrypt message
    let mut cipher = Aes256Ctr::new_var(key1, iv)?;
    cipher.apply_keystream(&mut ciphertext);
    let n = Pkcs7::unpad(&ciphertext)?.len();
    ciphertext.truncate(n);

    Ok(ciphertext)
}

/// Decrypt an ansible vault formated stream
///
/// Message should be formatted with lines of 80 chars and indentation. Function expects header to
/// be present but don't check format : lines of any length or any indentation will do
/// ```text
/// $ANSIBLE_VAULT;1.1;AES256
///       33666638363066623664653234386231616339646438303933633830376132633330353032393364
///       3363373531316565663539326661393165323030383934380a366133633066623963303665303238
///       34633364626339313035633763313034366538363537306265316532663531363632383333353737
///       3863616362363731660a666161623033666331663937626433313432616266393830376431393665
///       3965
///```
/// # Arguments:
/// * `input`: a stream of encrypted message with ansible-vault header
/// * `key`: the key to decrypt the message
pub fn decrypt_vault<T: Read>(input: T, key: &str) -> Result<Vec<u8>> {
    let mut lines = std::io::BufReader::new(input).lines();
    let first: String = lines
        .next()
        .ok_or_else(|| VaultError::from_kind(ErrorKind::NotAVault))??;
    let payload = lines
        .filter_map(|i| i.ok())
        .map(|s| s.trim().to_owned())
        .collect::<Vec<String>>()
        .join("");

    if first != VAULT_1_1_PREFIX {
        return Err(VaultError::from_kind(ErrorKind::NotAVault));
    }

    decrypt(payload.as_bytes(), key)
}

/// Decrypt an ansible vault file using a key.
///
/// A wrapper for decrypt_vault method.
///
/// # Arguments:
/// * `path`: the path to the encrypted vault file (&str, PathBuf, etc…)
/// * `key`: the key to decrypt the file
///
pub fn decrypt_vault_from_file<P: AsRef<Path>>(path: P, key: &str) -> Result<Vec<u8>> {
    let f = File::open(path)?;
    decrypt_vault(f, key)
}

/// Encrypt a message to an ansible vault formated string
///
/// The output will be formatted with the ansible_vault header (1.1) an 80 chars lines and 6 spaces
/// indentation.
/// ```text
/// $ANSIBLE_VAULT;1.1;AES256
///       33666638363066623664653234386231616339646438303933633830376132633330353032393364
///       3363373531316565663539326661393165323030383934380a366133633066623963303665303238
///       34633364626339313035633763313034366538363537306265316532663531363632383333353737
///       3863616362363731660a666161623033666331663937626433313432616266393830376431393665
///       3965
///```
/// # Arguments:
/// * `input`: a stream to the data to encrypt
/// * `key`: the key to encrypt the message
pub fn encrypt_vault<T: Read>(input: T, key: &str) -> Result<String> {
    let line_length = 80;
    let ciphertext = encrypt(input, key)?;
    let mut buffer = Vec::new();
    for chunk in ciphertext.into_bytes().chunks(line_length) {
        let mut line = ["      ".as_bytes(), chunk, "\n".as_bytes()].concat();
        buffer.append(&mut line);
    }

    let vault_text = format! {"{}\n{}", VAULT_1_1_PREFIX, String::from_utf8(buffer)?};

    Ok(vault_text)
}

/// Encrypt message to string without formatting (no header, no carriage returns)
///
/// # Arguments
/// * `input` : a data reader (&[u8], file, etc…) to the message
/// * `key` : the key to use encrypt
///
/// # Example
/// ```rust, no_run
///  # use ansible_vault::encrypt;
///  let lipsum = "Lorem ipsum dolor";
///  let decoded = encrypt(lipsum.as_bytes(),"hush").unwrap();
/// ```
pub fn encrypt<T: Read>(mut input: T, key: &str) -> Result<String> {
    // Pad input data
    let mut buffer = Vec::new();
    input.read_to_end(&mut buffer)?;
    let pos = buffer.len();
    let pad_len = AES_BLOCK_SIZE - (pos % AES_BLOCK_SIZE);
    buffer.resize(pos + pad_len, 0);
    let mut block_buffer = Pkcs7::pad(buffer.as_mut_slice(), pos, AES_BLOCK_SIZE)?;

    // Derive cryptographic keys
    let salt = rand::thread_rng().gen::<[u8; 32]>();
    let (key1, key2, iv) = &generate_derived_key(key, &salt);

    // Encrypt data
    let mut cipher = Aes256Ctr::new_var(key1, iv)?;
    cipher.apply_keystream(&mut block_buffer);

    // Message authentication
    let mut mac = HmacSha256::new_varkey(key2)?;
    mac.update(block_buffer);
    let result = mac.finalize();
    let b_hmac = result.into_bytes();

    // Format data
    let ciphertext = format!(
        "{}\n{}\n{}",
        hex::encode(salt),
        hex::encode(b_hmac),
        hex::encode(block_buffer)
    );

    Ok(hex::encode(ciphertext))
}

/// Encrypt a file to an ansible_vault string
///
/// A wrapper for encrypt_vault method.
///
/// # Arguments:
/// * `path`: the path to the file to encrypt
/// * `key`: the key to encrypt the file
///
pub fn encrypt_vault_from_file<P: AsRef<Path>>(path: P, key: &str) -> Result<String> {
    let f = File::open(path)?;
    encrypt_vault(f, key)
}

#[cfg(test)]
mod tests {
    use crate::errors::{ErrorKind, VaultError};
    use std::fs;

    const LIPSUM_PATH: &str = "./test/lipsum.txt";
    const LIPSUM_VAULT_PATH: &str = "./test/lipsum.vault";
    const LIPSUM_SECRET: &str = "shibboleet";

    #[test]
    fn test_wrong_password() {
        let result = crate::decrypt_vault_from_file(LIPSUM_VAULT_PATH, "p@$$w0rd").unwrap_err();
        assert_eq!(result, VaultError::from_kind(ErrorKind::IncorrectSecret));
    }

    #[test]
    fn test_decrypt() {
        let buf = crate::decrypt_vault_from_file(LIPSUM_VAULT_PATH, LIPSUM_SECRET).unwrap();
        let lipsum = String::from_utf8(buf).unwrap();
        let reference = fs::read_to_string(LIPSUM_PATH).unwrap();
        assert_eq!(lipsum, reference);
    }

    #[test]
    fn test_encrypt() {
        let lipsum = fs::read_to_string(LIPSUM_PATH).unwrap();
        let encoded = crate::encrypt_vault_from_file(LIPSUM_PATH, LIPSUM_SECRET).unwrap();
        let decoded = crate::decrypt_vault(encoded.as_bytes(), LIPSUM_SECRET).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(lipsum, decoded_str);
    }
}
