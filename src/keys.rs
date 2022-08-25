//! This module provides the functions required to generate keys from passwords
use pbkdf2::{
    password_hash::PasswordHasher,
    Pbkdf2,
};
pub use pbkdf2::password_hash::SaltString;
use rand::rngs::OsRng;

// Salt length is 22 bytes
pub const SALT_LENGTH: usize = 22;
pub const KEY_LENGTH: usize = 32;
pub type Aes256KeyBytes = [u8; KEY_LENGTH];

#[derive(Debug)]
pub enum KeyError {
    InvalidKeyLength,
}

/// A function to generate a SaltString struct, from the pbkdf2 crate
pub fn generate_salt() -> SaltString {
    SaltString::generate(OsRng)
}

/// Generate the AES-256 key bytes from a password and salt. The function will return an array
/// of 32 bytes (256 bits)
pub fn get_key_bytes_from_pw(password: &str, salt: &SaltString) -> [u8; 32] {
    let password_bytes = password.as_bytes();
    let hash_struct = match Pbkdf2.hash_password(password_bytes, salt) {
        Ok(hash_struct) => hash_struct,
        // TODO: FIX THIS TO HANDLE BETTER!
        Err(e) => panic!("{}", e),
    };
    let hash = match hash_struct.hash {
        Some(hash) => hash,
        None => panic!("Help"),
    };
    let bytes = hash.as_bytes();
    let ret_bytes = &bytes[0..32];
    match ret_bytes.try_into() {
        Ok(ret_bytes) => ret_bytes,
        Err(e) => panic!("{}", e),
    }
}

pub fn coerce_slice_to_key_array(slice: &[u8]) -> Result<Aes256KeyBytes, KeyError> {
    let key: Aes256KeyBytes = match slice.try_into() {
        Ok(key) => key,
        Err(_) => return Err(KeyError::InvalidKeyLength),
    };
    Ok(key)
}

#[cfg(test)]
mod tests {
    use crate::keys::generate_salt;

    use super::get_key_bytes_from_pw;

    #[test]
    fn test_get_key_bytes_from_pw() {
        let password = "hunter42";
        let salt = generate_salt();
        let arr = get_key_bytes_from_pw(password, &salt);
        assert!(arr.len() == 32);
    }
}
