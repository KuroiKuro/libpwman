//! This module provides the functionality related to encryption and decryption
//! 
//! `libpwman` uses the `AES-256-GCM` symmetric encryption algorithm. Different encryption
//! algorithms may be used as well, however it will require developers to implement the relevant
//! traits themselves

use crate::keys::Aes256KeyBytes;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use generic_array::GenericArray;
use rand::{rngs::OsRng, RngCore};
use std::str;

/// An enum representing the possible error states encountered during encryption and decryption.
#[derive(Debug)]
pub enum CryptError {
    EncryptionError,
    DecryptionError,
}

/// The length of the nonce for `AES-256-GCM`, as the number of bytes.
pub const NONCE_LENGTH: usize = 12;
/// Type representing an array of bytes with the length of the nonce.
pub type Aes256GcmNonce = [u8; NONCE_LENGTH];

/// A struct to assist with encrypting and decrypting with AES-256-GCM. Uses RustCrypto's
/// `aes_gcm` crate
pub struct Aes256GcmCrypt {
    nonce: Aes256GcmNonce,
    key: Aes256KeyBytes,
}

impl Aes256GcmCrypt {
    /// Create a new instance of Aes256GcmCrypt with a new randomly generated nonce
    pub fn new(key: &Aes256KeyBytes) -> Aes256GcmCrypt {
        let nonce: Aes256GcmNonce = Aes256GcmCrypt::generate_nonce();
        Aes256GcmCrypt { nonce, key: *key }
    }

    /// Create a new instance of Aes256GcmCrypt with a pre-existing nonce
    pub fn from_nonce(key: &Aes256KeyBytes, nonce: &Aes256GcmNonce) -> Aes256GcmCrypt {
        Aes256GcmCrypt {
            nonce: *nonce,
            key: *key,
        }
    }

    /// Generate a nonce that can be used in the AES-256-GCM algorithm
    pub fn generate_nonce() -> Aes256GcmNonce {
        let mut nonce: Aes256GcmNonce = [0; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
    
    /// Gets the nonce from the struct
    pub fn get_nonce(&self) -> Aes256GcmNonce {
        self.nonce
    }
}

/// This trait provides an interface for structs to provide encryption and decryption operations
/// 
/// Different encryption algorithms may be supported by implementing this trait for them.
pub trait Crypt {
    /// Encrypt a plaintext string password and output the bytes
    fn encrypt_str(&self, plaintext: &str) -> Result<Vec<u8>, CryptError>;
    /// Decrypt a ciphertext string password and output the bytes
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptError>;
    /// Encrypt a plaintext byte slice and output the bytes
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptError>;
}

impl Crypt for Aes256GcmCrypt {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptError> {
        let key = GenericArray::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&self.nonce);

        match cipher.encrypt(nonce, plaintext) {
            Ok(result) => Ok(result),
            Err(_) => Err(CryptError::EncryptionError),
        }
    }
    /// Encrypts a plaintext with AES-256-GCM
    fn encrypt_str(&self, plaintext: &str) -> Result<Vec<u8>, CryptError> {
        self.encrypt(plaintext.as_bytes())
    }

    /// Decrypts a plaintext with AES-256-GCM
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptError> {
        let key = GenericArray::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&self.nonce);

        match cipher.decrypt(nonce, ciphertext) {
            Ok(result) => Ok(result),
            Err(_e) => Err(CryptError::DecryptionError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Aes256GcmCrypt, Aes256KeyBytes, Crypt, NONCE_LENGTH};
    use crate::keys::{generate_salt, get_key_bytes_from_pw};
    use pbkdf2::password_hash::SaltString;

    fn generate_key() -> (Aes256KeyBytes, SaltString) {
        let salt = generate_salt();
        let key = get_key_bytes_from_pw("password", &salt);
        (key, salt)
    }

    #[test]
    fn test_aes256gcmcrypt_crypt() {
        let (key, _salt) = generate_key();
        let crypt = Aes256GcmCrypt::new(&key);

        // Test that after encryption and decryption, we get the same value
        let plaintext = "I am Malenia, Blade of Miquella";
        let ciphertext = match crypt.encrypt_str(plaintext) {
            Ok(ciphertext) => ciphertext,
            Err(_) => panic!("Encryption encountered an error"),
        };

        let nonce = crypt.nonce;
        let new_crypt = Aes256GcmCrypt::from_nonce(&key, &nonce);
        let decrypted_ciphertext = match new_crypt.decrypt(&ciphertext) {
            Ok(text) => text,
            Err(_) => panic!("Decryption encountered an error"),
        };
        assert_eq!(plaintext.as_bytes(), decrypted_ciphertext);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = Aes256GcmCrypt::generate_nonce();
        assert_eq!(nonce.len(), NONCE_LENGTH);
    }
}
