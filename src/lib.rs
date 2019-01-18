#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    NotAVault,
    InvalidFormat,
    IncorrectSecret,
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::cmp::PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        match (self, other) {
            (Error::IoError(_), Error::IoError(_)) => true,
            (Error::NotAVault, Error::NotAVault) => true,
            (Error::InvalidFormat, Error::InvalidFormat) => true,
            (Error::IncorrectSecret, Error::IncorrectSecret) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::IoError(err) => err.fmt(f),
            _ => {
                use std::error::Error;
                write!(f, "{}", self.description())
            }
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::IoError(err) => err.description(),
            Error::NotAVault => "file is not an ansible vault",
            Error::InvalidFormat => "file is a broken ansible vault",
            Error::IncorrectSecret => "incorrect secret for ansible vault",
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            Error::IoError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(_error: std::string::FromUtf8Error) -> Self {
        Error::InvalidFormat
    }
}

impl From<base16::DecodeError> for Error {
    fn from(_error: base16::DecodeError) -> Self {
        Error::InvalidFormat
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for Error {
    fn from(_error: hmac::crypto_mac::InvalidKeyLength) -> Self {
        Error::InvalidFormat
    }
}

fn read_hex_lines<T: std::io::BufRead>(lines: std::io::Lines<T>) -> Result<Vec<u8>> {
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
fn verify_vault(key: &[u8], ciphertext: &[u8], crypted_hmac: &[u8]) -> Result<bool> {
    use hmac::Mac;

    let mut hmac = hmac::Hmac::<sha2::Sha256>::new_varkey(key)?;
    hmac.input(&ciphertext);

    Ok(hmac.result().code().as_slice().eq(crypted_hmac)) // Constant time equivalence is not required for this use case.
}

pub fn read_vault<T: std::io::Read>(input: T, key: &str) -> Result<Vec<u8>> {
    use std::io::BufRead;

    let mut lines = std::io::BufReader::new(input).lines();
    let first: String = lines.next().ok_or(Error::NotAVault)??;

    if first != "$ANSIBLE_VAULT;1.1;AES256" {
        return Err(Error::NotAVault);
    }

    let inner = String::from_utf8(read_hex_lines(lines)?)?;

    let mut lines = inner.lines();

    let salt = base16::decode(&lines.next().ok_or(Error::InvalidFormat)?)?;
    let hmac_verify = base16::decode(&lines.next().ok_or(Error::InvalidFormat)?)?;
    let mut ciphertext = base16::decode(&lines.next().ok_or(Error::InvalidFormat)?)?;

    let mut hmac_buffer = [0; 80];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(key.as_bytes(), &salt, 10000, &mut hmac_buffer);

    let key1 = &hmac_buffer[0..32];
    let key2 = &hmac_buffer[32..64];
    let iv = &hmac_buffer[64..80];

    if !verify_vault(key2, &ciphertext, &hmac_verify)? {
        return Err(Error::IncorrectSecret);
    }

    use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
    let mut cipher = aes_ctr::Aes256Ctr::new_var(key1, iv).map_err(|_err| Error::InvalidFormat)?;

    cipher.apply_keystream(&mut ciphertext);
    pkcs7::un_pad(&mut ciphertext);

    Ok(ciphertext)
}

pub fn read_vault_from_file(path: &std::path::Path, key: &str) -> Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    read_vault(f, key)
}

#[cfg(test)]
mod tests {
    fn lipsum_path() -> std::path::PathBuf {
        use std::str::FromStr;
        std::path::PathBuf::from_str("./test/lipsum.vault").unwrap()
    }

    #[test]
    fn wrong_password() {
        let result = crate::read_vault_from_file(&lipsum_path(), "not shibboleet").unwrap_err();
        std::assert_eq!(result, crate::Error::IncorrectSecret);
    }

    #[test]
    fn contents() {
        let buf = crate::read_vault_from_file(&lipsum_path(), "shibboleet").unwrap();
        let lipsum = std::string::String::from_utf8(buf).unwrap();
        let reference = std::fs::read_to_string("./test/lipsum.txt").unwrap();
        std::assert_eq!(lipsum, reference);
    }
}
