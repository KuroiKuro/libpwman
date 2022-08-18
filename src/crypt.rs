use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

pub enum CryptError {
    EncryptionError,
    DecryptionError
}

pub type Aes256KeyBytes = [u8; 32];


/// A struct to assist with encrypting and decrypting with AES-256-GCM. Uses RustCrypto's
/// `aes_gcm` crate
pub struct Aes256GcmCrypt {
    nonce: [u8; 12],
    key: Aes256KeyBytes,
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
