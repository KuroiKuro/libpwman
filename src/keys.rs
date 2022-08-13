//! This module provides the functions required to generate keys from passwords
use pbkdf2::{
    password_hash::{errors, PasswordHash, PasswordHasher, SaltString},
    Pbkdf2,
};
use rand::rngs::OsRng;

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
