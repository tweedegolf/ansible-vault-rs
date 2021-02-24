//! Decrypting of Ansible vault 1.1 files and streams.
//!
//! This crate provides the `read_vault` function which will decrypt an
//! ansible vault and yield a byte buffer of the plaintext.
//! It detects incorrect vault secrets and incorrectly formatted vaults,
//! and yields the appropriate errors.

use aes_ctr::cipher::{NewStreamCipher, SyncStreamCipher};
use block_padding::{Padding, Pkcs7};
use hmac::{Hmac, Mac, NewMac};
use pbkdf2::pbkdf2;
use rand::{thread_rng, Rng};
use sha2::Sha256;
use std::io::BufRead;
use thiserror::Error;

/// The error type for decrypting Ansible vaults.
///
/// Errors either originate from failing I/O operations, or from
/// passing incorrect (formatted) files, streams or secrets.
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("IO error")]
    IoError(#[from] std::io::Error),
    #[error("Error encoding UTF-8")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("Error padding input")]
    PaddingError,
    #[error("file is not an ansible vault")]
    NotAVault,
    #[error("file is a broken ansible vault")]
    InvalidFormat,
    #[error("incorrect secret for ansible vault")]
    IncorrectSecret,
}

impl From<std::string::FromUtf8Error> for VaultError {
    fn from(_error: std::string::FromUtf8Error) -> Self {
        VaultError::InvalidFormat
    }
}

impl From<base16::DecodeError> for VaultError {
    fn from(_error: base16::DecodeError) -> Self {
        VaultError::InvalidFormat
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for VaultError {
    fn from(_error: hmac::crypto_mac::InvalidKeyLength) -> Self {
        VaultError::InvalidFormat
    }
}

fn read_hex_lines<T: std::io::BufRead>(lines: std::io::Lines<T>) -> Result<Vec<u8>, VaultError> {
    let mut buffer: Vec<u8> = vec![];

    let mut i = 0;
    for line in lines {
        let line = line?;
        let part_len = line.len() / 2;

        buffer.resize(i + part_len, 0);
        let (_, dest) = buffer.as_mut_slice().split_at_mut(i);
        i += part_len;

        base16::decode_slice(line.as_bytes(), dest)?;
    }

    Ok(buffer)
}

/// See https://github.com/ansible/ansible/blob/devel/lib/ansible/parsing/vault/__init__.py#L1286.
fn verify_vault(key: &[u8], ciphertext: &[u8], crypted_hmac: &[u8]) -> Result<bool, VaultError> {
    let mut hmac = Hmac::<Sha256>::new_varkey(key)?;
    hmac.update(&ciphertext);
    let result = hmac.finalize();

    Ok(result.into_bytes().as_slice().eq(crypted_hmac)) // Constant time equivalence is not required for this use case.
}

/// Decrypt an ansible vault stream using a key.
///
/// When succesful, yields a plaintext byte buffer.
pub fn read_vault<T: std::io::Read>(input: T, key: &str) -> Result<Vec<u8>, VaultError> {
    let mut lines = std::io::BufReader::new(input).lines();
    let first: String = lines.next().ok_or(VaultError::NotAVault)??;

    if first != "$ANSIBLE_VAULT;1.1;AES256" {
        return Err(VaultError::NotAVault);
    }

    let inner = String::from_utf8(read_hex_lines(lines)?)?;

    let mut lines = inner.lines();

    let salt = base16::decode(&lines.next().ok_or(VaultError::InvalidFormat)?)?;
    let hmac_verify = base16::decode(&lines.next().ok_or(VaultError::InvalidFormat)?)?;
    let mut ciphertext = base16::decode(&lines.next().ok_or(VaultError::InvalidFormat)?)?;

    let mut hmac_buffer = [0; 80];
    pbkdf2::<Hmac<Sha256>>(key.as_bytes(), &salt, 10000, &mut hmac_buffer);

    let key1 = &hmac_buffer[0..32];
    let key2 = &hmac_buffer[32..64];
    let iv = &hmac_buffer[64..80];

    if !verify_vault(key2, &ciphertext, &hmac_verify)? {
        return Err(VaultError::IncorrectSecret);
    }

    let mut cipher =
        aes_ctr::Aes256Ctr::new_var(key1, iv).map_err(|_err| VaultError::InvalidFormat)?;

    cipher.apply_keystream(&mut ciphertext);
    let n = Pkcs7::unpad(&ciphertext)
        .map_err(|_| VaultError::InvalidFormat)?
        .len();
    ciphertext.truncate(n);

    Ok(ciphertext)
}

pub fn write_vault(input: &mut [u8], key: &str) -> Result<String, VaultError> {
    let mut rng = thread_rng();
    let salt: [u8; 32] = rng.gen();

    let mut hmac_buffer = [0; 80];
    pbkdf2::<Hmac<Sha256>>(key.as_bytes(), &salt, 10000, &mut hmac_buffer);

    let key1 = &hmac_buffer[0..32];
    let key2 = &hmac_buffer[32..64];
    let iv = &hmac_buffer[64..80];

    let mut cipher =
        aes_ctr::Aes256Ctr::new_var(key1, iv).map_err(|_err| VaultError::InvalidFormat)?;

    let n = input.len();
    let offset = (n % 128) * 8;
    let mut buffer = input.to_vec();
    buffer.resize(n + offset, 0);
    let n = Pkcs7::pad(&mut buffer, n, 128)
        .map_err(|_err| VaultError::PaddingError)?
        .len();
    buffer.truncate(n);

    cipher.apply_keystream(&mut buffer);

    let mut hmac = Hmac::<Sha256>::new_varkey(key2)?;
    hmac.update(&buffer);
    let hmac_verify = hmac.finalize();

    let mut output = vec!["$ANSIBLE_VAULT;1.1;AES256".as_bytes()];
    let salt = base16::encode_upper(&salt);
    let hmac_verify = base16::encode_upper(&hmac_verify.into_bytes());
    let lines = format!(
        "{}\n{}\n{}",
        salt,
        hmac_verify,
        base16::encode_upper(&buffer)
    );
    let mut lines = base16::encode_upper(&lines).as_bytes().to_owned();
    for line in lines.chunks_mut(80) {
        output.push(line);
    }
    Ok(std::string::String::from_utf8(
        output.join("\n".as_bytes()),
    )?)
}

/// Decrypt an ansible vault file using a key.
///
/// When succesful, yields a plaintext byte buffer.
pub fn read_vault_from_file(path: &std::path::Path, key: &str) -> Result<Vec<u8>, VaultError> {
    let f = std::fs::File::open(path)?;
    read_vault(f, key)
}

#[cfg(test)]
mod tests {
    use std::{io::Read, str::FromStr};

    fn lipsum_path() -> std::path::PathBuf {
        std::path::PathBuf::from_str("./test/lipsum.vault").unwrap()
    }

    #[test]
    fn wrong_password() {
        let result = crate::read_vault_from_file(&lipsum_path(), "not shibboleet").unwrap_err();
        match result {
            crate::VaultError::IncorrectSecret => {}
            _ => panic!(),
        }
    }

    #[test]
    fn contents() {
        let buf = crate::read_vault_from_file(&lipsum_path(), "shibboleet").unwrap();
        let lipsum = std::string::String::from_utf8(buf).unwrap();
        let reference = std::fs::read_to_string("./test/lipsum.txt").unwrap();
        std::assert_eq!(lipsum, reference);
    }

    #[test]
    fn encrypt() {
        let reference = std::fs::read_to_string("./test/lipsum.txt").unwrap();
        let mut bytes = std::fs::read("./test/lipsum.txt").unwrap();
        let lipsum = crate::write_vault(&mut bytes, "shibboleet").unwrap();
        let unencrypted = std::string::String::from_utf8(
            crate::read_vault(lipsum.as_bytes(), "shibboleet").unwrap(),
        )
        .unwrap();
        std::assert_eq!(unencrypted, reference);
    }
}
