//! This module provides the functions required to generate keys from passwords
use pbkdf2::{
    password_hash::{errors, PasswordHash, PasswordHasher, SaltString},
    Pbkdf2,
};
use rand::rngs::OsRng;

pub fn generate_pw_hash(password: &str) -> [u8; 32] {
    let salt = SaltString::generate(OsRng);
    let password_bytes = password.as_bytes();
    let hash_struct = match Pbkdf2.hash_password(password_bytes, &salt) {
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
    use super::generate_pw_hash;

    #[test]
    fn test_generate_pw_hash() {
        let password = "hunter42";
        let arr = generate_pw_hash(password);
        assert!(arr.len() == 32);
    }
}
