//! This module provides the functionality for the password database

use crate::crypt::{Aes256GcmCrypt, Aes256GcmNonce, Crypt, CryptError};
use crate::keys::{coerce_slice_to_key_array, Aes256KeyBytes, KeyError};
use std::collections::HashMap;
use std::str;

pub const DB_VERSION: &str = "0.1";

/// Enum to represent possible errors when saving or retrieving passwords from the PasswordEntry
/// struct
pub enum PasswordEntryError {
    CryptError { e: CryptError },
    KeyError { e: KeyError },
    PasswordSaveError,
    PasswordEncodingError,
}

/// A struct representing a password entry in the password database. A PasswordEntry
/// contains all the relevant information that a user would desire to store together with
/// a password, such as the username etc. The password that is saved in the struct will be
/// encrypted, and should be decrypted on demand. The implementation of PasswordEntry in this
/// crate makes use of AES-256-GCM to encrypt and decrypt the password. A new nonce is generated
/// for each PasswordEntry created
pub struct PasswordEntry {
    title: Option<String>,
    enc_password: Option<Vec<u8>>,
    username: Option<String>,
    urls: Option<Vec<String>>,
    notes: Option<String>,
    custom_fields: HashMap<String, String>,
    // Nonce info, used for encryption and decryption with AES-256-GCM
    nonce: Aes256GcmNonce,
}

impl PasswordEntry {
    /// Generate a new empty `PasswordEntry`
    pub fn new() -> PasswordEntry {
        PasswordEntry {
            title: None,
            enc_password: None,
            username: None,
            urls: None,
            notes: None,
            custom_fields: HashMap::new(),
            nonce: Aes256GcmCrypt::generate_nonce(),
        }
    }
    pub fn new_from_args(
        title: Option<String>,
        enc_password: Option<Vec<u8>>,
        username: Option<String>,
        urls: Option<Vec<String>>,
        notes: Option<String>,
        custom_fields: Option<HashMap<String, String>>,
    ) -> PasswordEntry {
        let save_custom_fields = match custom_fields {
            Some(custom_fields) => custom_fields,
            None => HashMap::new(),
        };
        PasswordEntry {
            title: title,
            enc_password: enc_password,
            username: username,
            urls: urls,
            notes: notes,
            custom_fields: save_custom_fields,
            nonce: Aes256GcmCrypt::generate_nonce(),
        }
    }
}

impl Default for PasswordEntry {
    fn default() -> Self {
        PasswordEntry::new()
    }
}

/// This trait is for structs that can encrypt and decrypt a password that it stores. For
/// example, one can refer to the PasswordEntry struct to see how it can be used in practice
pub trait PasswordEntryCrypt {
    /// Types implementing this trait will use the `save_password` method to save a plaintext
    /// password into self in an encrypted form. The `enc_key` argument is intentionally left as a
    /// slice of indeterminate length to allow types to implement the encryption using keys of a
    /// varying length, depending on the specification of the encryption algorithm
    fn save_password(&mut self, password: &str, enc_key: &[u8]) -> Result<(), PasswordEntryError>;
    /// Types implementing this trait will use the `get_password` method to retrieve a plaintext
    /// password from the encrypted password saved in the struct. The `enc_key` argument is
    /// intentionally left as a slice of indeterminate length to allow types to implement the
    /// encryption using keys of varying length, depending on the specification of the
    /// encryption algorithm. The returned valid result should be of type Option<String> to handle
    /// cases where the `get_password` method was called on a struct instance that did not have a
    /// password saved
    fn get_password(&self, enc_key: &[u8]) -> Result<Option<String>, PasswordEntryError>;
}

impl PasswordEntryCrypt for PasswordEntry {
    fn save_password(&mut self, password: &str, enc_key: &[u8]) -> Result<(), PasswordEntryError> {
        // Create the key array, based on coercing the enc_key slice into an array of the length
        // required for an AES-256 key
        let key: Aes256KeyBytes = match coerce_slice_to_key_array(enc_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(PasswordEntryError::KeyError {
                    e: KeyError::InvalidKeyLength,
                })
            }
        };

        // Initialize the cipher object and encrypt the password
        let crypt = Aes256GcmCrypt::new(&key);
        let ciphertext = match crypt.encrypt(password) {
            Ok(data) => data,
            Err(e) => {
                return Err(PasswordEntryError::CryptError {
                    e: CryptError::EncryptionError,
                })
            }
        };

        self.enc_password = Some(ciphertext);
        Ok(())
    }

    fn get_password(&self, enc_key: &[u8]) -> Result<Option<String>, PasswordEntryError> {
        // If there is no key saved in the struct, then return None
        let enc_password = match &self.enc_password {
            Some(password) => password,
            None => return Ok(None),
        };

        // Create the key array, based on coercing the enc_key slice into an array of the length
        // required for an AES-256 key
        let key: Aes256KeyBytes = match coerce_slice_to_key_array(enc_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(PasswordEntryError::KeyError {
                    e: KeyError::InvalidKeyLength,
                })
            }
        };

        // Initialize the cipher object and decrypt the password
        let crypt = Aes256GcmCrypt::new(&key);
        let plaintext = match crypt.decrypt(&enc_password) {
            Ok(data) => data,
            Err(e) => {
                return Err(PasswordEntryError::CryptError {
                    e: CryptError::DecryptionError,
                })
            }
        };

        let password_string = match str::from_utf8(&plaintext) {
            Ok(pw) => pw,
            Err(_) => return Err(PasswordEntryError::PasswordEncodingError),
        };

        Ok(Some(password_string.to_owned()))
    }
}

// pub struct PasswordDb {
//     key: [u8; 32],
//     salt: [u8; SALT_LENGTH],
//     // Placeholder first, replace with a better datastructure
//     passwords: HashMap<u32, PasswordEntry>,
//     db_version: String,
// }

// impl PasswordDb {
//     fn new(db_password: &str) {
//         let salt = generate_salt();
//         let key_bytes = get_key_bytes_from_pw(db_password, &salt);
//         let salt_len = salt.as_bytes().len();
//         panic!("salt_len =  {}", salt_len);
//         // let salt_str =
//     }
// }

#[cfg(test)]
mod tests {
    // use super::PasswordDb;

    // #[test]
    // fn test_new() {
    //     PasswordDb::new("test");
    // }
}
