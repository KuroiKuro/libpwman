//! This module provides the functionality for the password database

use crate::crypt::{Aes256GcmCrypt, Aes256GcmNonce, Crypt, CryptError};
use crate::keys::{
    coerce_slice_to_key_array, Aes256KeyBytes, KeyError,
};
use std::collections::HashMap;
use std::str;

pub const DB_VERSION: &str = "0.1";

/// Enum to represent possible errors when saving or retrieving passwords from the `PasswordEntry`
/// struct
#[derive(Debug)]
pub enum PasswordEntryError {
    CryptError { e: CryptError },
    KeyError { e: KeyError },
    PasswordSaveError,
    PasswordEncodingError,
}

/// A struct representing a password entry in the password database. A `PasswordEntry`
/// contains all the relevant information that a user would desire to store together with
/// a password, such as the username etc. The password that is saved in the struct will be
/// encrypted, and should be decrypted on demand. The implementation of `PasswordEntry` in this
/// crate makes use of `AES-256-GCM` to encrypt and decrypt the password. A new nonce is generated
/// for each `PasswordEntry` created.
///
/// Note that the fields apart from the actual password fields are public fields here. This is to
/// allow access to them without any API methods, which will be very simple getter and setters
/// anyway. This will allow custom struct types that replace `PasswordEntry` to be easily dropped
/// in to custom code that can access different fields directly without an API
pub struct PasswordEntry {
    pub title: Option<String>,
    enc_password: Option<Vec<u8>>,
    pub username: Option<String>,
    pub urls: Option<Vec<String>>,
    pub notes: Option<String>,
    pub custom_fields: HashMap<String, String>,
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
    /// Create a new instance of `PasswordEntry` with the arguments saved as data in the new entry
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
            title,
            enc_password,
            username,
            urls,
            notes,
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
/// example, one can refer to the PasswordEntry struct to see how it can be used in practice.
/// Implement this trait for any custom structs that are intended to replace the default
/// `PasswordEntry` struct for use in password databases
pub trait PasswordEntryCrypt {
    /// A type that implements the Crypt trait. This can be used in the implementations of the
    /// trait methods for encryption and decryption purposes
    type CryptType: Crypt;

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
    type CryptType = Aes256GcmCrypt;

    /// Save a given password into the PasswordEntry instance
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
        let crypt = Self::CryptType::from_nonce(&key, &self.nonce);

        let plaintext = password;
        let ciphertext = match crypt.encrypt(plaintext) {
            Ok(ciphertext) => ciphertext,
            Err(_) => panic!("Encryption encountered an error"),
        };

        self.enc_password = Some(ciphertext);
        Ok(())
    }

    /// Retrieve and decrypt the saved password from the PasswordEntry instance. If there is no
    /// password currently saved, `None` will be returned
    fn get_password(&self, enc_key: &[u8]) -> Result<Option<String>, PasswordEntryError> {
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
        let nonce: Aes256GcmNonce = self.nonce;
        let crypt = Self::CryptType::from_nonce(&key, &nonce);
        let plaintext = match crypt.decrypt(enc_password) {
            Ok(data) => data,
            Err(_e) => {
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
    use super::*;
    use crate::keys::{generate_salt, get_key_bytes_from_pw};

    #[test]
    fn test_passwordentry_new() {
        let entry = PasswordEntry::new();
        assert_eq!(entry.title, None);
        assert_eq!(entry.username, None);
        assert_eq!(entry.enc_password, None);
        assert_eq!(entry.urls, None);
        assert_eq!(entry.notes, None);

        // Test custom fields
        assert_eq!(entry.custom_fields.len(), 0);
        // Test that a new nonce was generated
        let entry2 = PasswordEntry::new();
        assert_ne!(entry.nonce, entry2.nonce);
    }

    #[test]
    fn test_passwordentry_new_with_args() {
        let title = "Golden Order".to_string();
        let username = "goldmask".to_string();
        let urls = vec![
            "https://facebook.com".to_string(),
            "https://twitter.com".to_string(),
        ];
        let notes = "Burning the Erdtree is the first cardinal sin".to_string();
        let mut custom_fields: HashMap<String, String> = HashMap::new();
        custom_fields.insert("field1".to_string(), "value1".to_string());
        custom_fields.insert("field2".to_string(), "value2".to_string());

        let entry = PasswordEntry::new_from_args(
            Some(title.clone()),
            None,
            Some(username.clone()),
            Some(urls),
            Some(notes.clone()),
            Some(custom_fields.clone()),
        );

        assert_eq!(entry.title, Some(title));
        assert_eq!(entry.username, Some(username));
        assert_eq!(entry.notes, Some(notes));
        if let Some(entry_urls) = entry.urls {
            assert_eq!(entry_urls[0], "https://facebook.com");
            assert_eq!(entry_urls[1], "https://twitter.com");
        }

        let field1_count = entry
            .custom_fields
            .keys()
            .filter(|key| *key == "field1")
            .count();
        let field2_count = entry
            .custom_fields
            .keys()
            .filter(|key| *key == "field2")
            .count();
        assert_eq!(field1_count, 1);
        assert_eq!(field2_count, 1);

        match entry.custom_fields.get("field1") {
            Some(value) => assert_eq!(value, "value1"),
            None => panic!("Custom fields missing field 'field1'"),
        };
        match entry.custom_fields.get("field2") {
            Some(value) => assert_eq!(value, "value2"),
            None => panic!("Custom fields missing field 'field2'"),
        };
    }

    #[test]
    fn test_passwordentry_passwordentrycrypt_impl() {
        let db_password = "password";
        let salt = generate_salt();
        let key = get_key_bytes_from_pw(db_password, &salt);

        let mut entry = PasswordEntry::new();
        let password = "clouddistrict9999";
        if let Err(e) = entry.save_password(password, &key) {
            panic!("Saving password failed with an error: {:?}", e);
        };

        match entry.get_password(&key) {
            Ok(retrieved_pw) => assert_eq!(retrieved_pw, Some(password.to_string())),
            Err(e) => panic!("Retrieve password failed with an error: {:?}", e),
        };
    }
}
