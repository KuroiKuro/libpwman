use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use rand::{rngs::OsRng, RngCore};

pub enum CryptError {
    EncryptionError,
    DecryptionError
}

pub type Aes256KeyBytes = [u8; 32];
pub type Aes256GcmNonce = [u8; 12];


/// A struct to assist with encrypting and decrypting with AES-256-GCM. Uses RustCrypto's
/// `aes_gcm` crate
pub struct Aes256GcmCrypt {
    nonce: Aes256GcmNonce,
    key: Aes256KeyBytes,
}

impl Aes256GcmCrypt {
    pub fn new(key: Aes256KeyBytes) -> Aes256GcmCrypt {
        let mut nonce: Aes256GcmNonce = [];
        OsRng.fill_bytes(&nonce);
        Aes256GcmCrypt { nonce: nonce, key: key }
    }

    pub fn from_nonce(key: Aes256KeyBytes, nonce: Aes256GcmNonce) -> Aes256GcmCrypt {
        Aes256GcmCrypt { nonce: nonce, key: key }
    }
}

pub trait Crypt {
    fn encrypt(&self, plaintext: &str) -> Result<String, CryptError>;
    fn decrypt(&self, ciphertext: &str) -> Result<String, CryptError>;
}


impl Crypt for Aes256GcmCrypt {
    /// Encrypts a plaintext with AES-256-GCM
    fn encrypt(&self, plaintext: &str) -> Result<String, CryptError> {
        let cipher = Aes256Gcm::new(&self.key);
        match cipher.encrypt(&self.nonce, plaintext) {
            Ok(result) => Ok(result.into()),
            Err(_) => Err(CryptError::EncryptionError)
        }
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String, CryptError> {
        let cipher = Aes256Gcm::new(&self.key);
        match cipher.decrypt(&self.nonce, ciphertext) {
            Ok(result) => Ok(result.into()),
            Err(_) => Err(CryptError::DecryptionError)
        }
    }
}
