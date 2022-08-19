use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use rand::{rngs::OsRng, RngCore};
use generic_array::GenericArray;
use std::str;

pub enum CryptError {
    EncryptionError,
    DecryptionError,
}

pub const NONCE_LENGTH: usize = 12;
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
        Aes256GcmCrypt {
            nonce: nonce,
            key: *key,
        }
    }

    /// Create a new instance of Aes256GcmCrypt with a pre-existing nonce
    pub fn from_nonce(key: Aes256KeyBytes, nonce: Aes256GcmNonce) -> Aes256GcmCrypt {
        Aes256GcmCrypt {
            nonce: nonce,
            key: key,
        }
    }

    /// Generate a nonce that can be used in the AES-256-GCM algorithm
    pub fn generate_nonce() -> Aes256GcmNonce {
        let mut nonce: Aes256GcmNonce = [0; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
}

/// This trait provides an interface for structs to provide encryption and decryption operations
pub trait Crypt {
    /// Encrypt a plaintext password and output the bytes
    fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, CryptError>;
    /// Decrypt a ciphertext password and output the bytes
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptError>;
}

impl Crypt for Aes256GcmCrypt {
    /// Encrypts a plaintext with AES-256-GCM
    fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, CryptError> {
        let key = GenericArray::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&self.nonce);

        match cipher.encrypt(nonce, plaintext.as_bytes()) {
            Ok(result) => Ok(result),
            Err(_) => Err(CryptError::EncryptionError),
        }
    }

    /// Decrypts a plaintext with AES-256-GCM
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptError> {
        let key = GenericArray::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&self.nonce);

        match cipher.decrypt(nonce, ciphertext) {
            Ok(result) => Ok(result),
            Err(_) => Err(CryptError::DecryptionError),
        }
    }
}


#[cfg(test)]
mod tests {
    use pbkdf2::password_hash::SaltString;
    use super::{Aes256KeyBytes, Aes256GcmCrypt, Crypt, NONCE_LENGTH};
    use crate::keys::{generate_salt, get_key_bytes_from_pw};

    fn generate_key() -> (Aes256KeyBytes, SaltString) {
        let salt = generate_salt();
        let key = get_key_bytes_from_pw("password", &salt);
        (key, salt)
    }

    #[test]
    fn test_aes256gcmcrypt_crypt() {
        let (key, salt) = generate_key();
        let crypt = Aes256GcmCrypt::new(&key);

        // Test that after encryption and decryption, we get the same value
        let plaintext = "I am Malenia, Blade of Miquella";
        let ciphertext = match crypt.encrypt(plaintext) {
            Ok(ciphertext) => ciphertext,
            Err(_) => panic!("Encryption encountered an error")
        };
        let decrypted_ciphertext = match crypt.decrypt(&ciphertext) {
            Ok(text) => text,
            Err(_) => panic!("Decryption encountered an error")
        };
        assert_eq!(plaintext.as_bytes(), decrypted_ciphertext);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = Aes256GcmCrypt::generate_nonce();
        assert_eq!(nonce.len(), NONCE_LENGTH);
    }
}
