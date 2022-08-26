//! This module provides the functionality for the password database

use crate::crypt::{Aes256GcmCrypt, Aes256GcmNonce, Crypt, CryptError};
use crate::keys;
use std::collections::HashMap;
use std::str;

pub const DB_VERSION: &str = "0.1";

/// Enum to represent possible errors when saving or retrieving passwords from the `PasswordEntry`
/// struct
#[derive(Debug)]
pub enum PasswordEntryError {
    CryptError { e: CryptError },
    KeyError { e: keys::KeyError },
    PasswordSaveError,
    PasswordEncodingError,
}

/// A struct representing a password entry in the password database. A `PassEntry`
/// contains all the relevant information that a user would desire to store together with
/// a password, such as the username etc. The password that is saved in the struct will be
/// encrypted, and should be decrypted on demand. The implementation of `PassEntry` in this
/// crate makes use of `AES-256-GCM` to encrypt and decrypt the password. A new nonce is generated
/// for each `PassEntry` created.
///
/// Note that the fields apart from the actual password fields are public fields here. This is to
/// allow access to them without any API methods, which will be very simple getter and setters
/// anyway. This will allow custom struct types that replace `PassEntry` to be easily dropped
/// in to custom code that can access different fields directly without an API
pub struct PassEntry {
    pub title: Option<String>,
    enc_password: Option<Vec<u8>>,
    pub username: Option<String>,
    pub urls: Option<Vec<String>>,
    pub notes: Option<String>,
    pub custom_fields: HashMap<String, String>,
    // Nonce info, used for encryption and decryption with AES-256-GCM
    nonce: Aes256GcmNonce,
}

impl PassEntry {
    /// Generate a new empty `PassEntry`
    pub fn new() -> PassEntry {
        PassEntry {
            title: None,
            enc_password: None,
            username: None,
            urls: None,
            notes: None,
            custom_fields: HashMap::new(),
            nonce: Aes256GcmCrypt::generate_nonce(),
        }
    }
    /// Create a new instance of `PassEntry` with the arguments saved as data in the new entry
    pub fn new_from_args(
        title: Option<String>,
        enc_password: Option<Vec<u8>>,
        username: Option<String>,
        urls: Option<Vec<String>>,
        notes: Option<String>,
        custom_fields: Option<HashMap<String, String>>,
    ) -> PassEntry {
        let save_custom_fields = match custom_fields {
            Some(custom_fields) => custom_fields,
            None => HashMap::new(),
        };
        PassEntry {
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

impl Default for PassEntry {
    fn default() -> Self {
        PassEntry::new()
    }
}

/// This trait is for structs that can encrypt and decrypt a password that it stores. For
/// example, one can refer to the `PassEntry` struct to see how it can be used in practice.
/// Implement this trait for any custom structs that are intended to replace the default
/// `PassEntry` struct for use in password databases
pub trait PasswordEntry {
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

impl PasswordEntry for PassEntry {
    type CryptType = Aes256GcmCrypt;

    /// Save a given password into the `PassEntry` instance
    fn save_password(&mut self, password: &str, enc_key: &[u8]) -> Result<(), PasswordEntryError> {
        // Create the key array, based on coercing the enc_key slice into an array of the length
        // required for an AES-256 key
        let key: keys::Aes256KeyBytes = match keys::coerce_slice_to_key_array(enc_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(PasswordEntryError::KeyError {
                    e: keys::KeyError::InvalidKeyLength,
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

    /// Retrieve and decrypt the saved password from the `PassEntry` instance. If there is no
    /// password currently saved, `None` will be returned
    fn get_password(&self, enc_key: &[u8]) -> Result<Option<String>, PasswordEntryError> {
        let enc_password = match &self.enc_password {
            Some(password) => password,
            None => return Ok(None),
        };

        // Create the key array, based on coercing the enc_key slice into an array of the length
        // required for an AES-256 key
        let key: keys::Aes256KeyBytes = match keys::coerce_slice_to_key_array(enc_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(PasswordEntryError::KeyError {
                    e: keys::KeyError::InvalidKeyLength,
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


/// The `PassDb` struct represents an instance of a password database in `pwman`. The password
/// database is the datastructure containing the passwords that a user wishes to save. All entries
/// in the database are encrypted and decrypted using the same key per database, which is derived
/// from the password that a user supplies when creating a new, empty `PassDb` instance.
/// 
/// PassDb supports a generic type `T`, which can be any type that implements `PasswordEntryCrypt`.
/// The default implementation provided by `libpwman` implements `T` as `PasswordEntry`.
pub struct PassDb<T: PasswordEntry> {
    key: [u8; keys::KEY_LENGTH],
    salt: [u8; keys::SALT_LENGTH],
    // Placeholder first, replace with a better datastructure
    passwords: Vec<T>,
    db_version: String,
}

impl PassDb<PassEntry> {
    /// Create a new empty instance of `PassDb`. This will generate a new salt, and use the salt
    /// to derive a new key from the given password. Use this if you're creating a brand new
    /// database for the first time
    /// ```rust
    /// let new_db: PassDb = PassDb::new("my_example_password");
    /// ```
    pub fn new(db_password: &str) -> PassDb<PassEntry> {
        // TODO: Fix db_version setting after creating db file spec
        let salt = keys::generate_salt();
        let key = keys::get_key_bytes_from_pw(db_password, &salt);
        let salt_arr: [u8; keys::SALT_LENGTH] = match salt.as_bytes().try_into() {
            Ok(salt_arr) => salt_arr,
            Err(e) => panic!("Failed to convert salt to bytes! (Error: {})", e)
        };
        PassDb { key: key, salt: salt_arr, passwords: Vec::new(), db_version: DB_VERSION.to_string() }
    }

    // pub fn rebuild(key: [u8; keys::KEY_LENGTH], salt: [u8; keys::SALT_LENGTH]) -> PassDb<PasswordEntry> {
    //     // TODO: Fix db_version setting after creating db file spec
    //     PassDb { key: key, salt: salt, passwords: Vec::new(), db_version: DB_VERSION.to_string() }
    // }
}

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
    fn test_passentry_new() {
        let entry = PassEntry::new();
        assert_eq!(entry.title, None);
        assert_eq!(entry.username, None);
        assert_eq!(entry.enc_password, None);
        assert_eq!(entry.urls, None);
        assert_eq!(entry.notes, None);

        // Test custom fields
        assert_eq!(entry.custom_fields.len(), 0);
        // Test that a new nonce was generated
        let entry2 = PassEntry::new();
        assert_ne!(entry.nonce, entry2.nonce);
    }

    #[test]
    fn test_passentry_new_with_args() {
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

        let entry = PassEntry::new_from_args(
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
    fn test_passentry_passwordentrycrypt_impl() {
        let db_password = "password";
        let salt = generate_salt();
        let key = get_key_bytes_from_pw(db_password, &salt);

        let mut entry = PassEntry::new();
        let password = "clouddistrict9999";
        if let Err(e) = entry.save_password(password, &key) {
            panic!("Saving password failed with an error: {:?}", e);
        };

        match entry.get_password(&key) {
            Ok(retrieved_pw) => assert_eq!(retrieved_pw, Some(password.to_string())),
            Err(e) => panic!("Retrieve password failed with an error: {:?}", e),
        };
    }

    #[test]
    fn test_passdb_new() {
        // Test that creating new PassDb instance does not panic
        PassDb::new("testpw");
    }
}
