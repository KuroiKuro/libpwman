//! This module provides the functionality for the password database

use std::str;
use crate::pwdb::passentry::{PassEntry, PasswordEntry};
use crate::keys;

pub const DB_VERSION: &str = "1.1";

/// The `PassDb` struct represents an instance of a password database in `pwman` which is the
/// datastructure containing the passwords that a user wishes to save.
/// 
/// All entries in the database are encrypted and decrypted using the same key per database, 
/// which is derived from the password that a user supplies when creating a new, empty
/// `PassDb` instance.
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
    /// use libpwman::pwdb::{PassDb, PassEntry};
    /// 
    /// let new_db: PassDb<PassEntry> = PassDb::new("my_example_password");
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

    /// Rebuild a `PassDb` that was previously created before from its key, salt and password entries
    pub fn rebuild(key: [u8; keys::KEY_LENGTH], salt: [u8; keys::SALT_LENGTH], password_entries: Vec<PassEntry>) -> PassDb<PassEntry> {
        // TODO: Fix db_version setting after creating db file spec
        PassDb { key: key, salt: salt, passwords: password_entries, db_version: DB_VERSION.to_string() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passdb_new() {
        // Test that creating new PassDb instance does not panic
        PassDb::new("testpw");
    }

    #[test]
    fn test_passdb_rebuild() {
        // Test that we can reuse the same key and salt that was created in a new PassDb
        // instance to rebuild it from scratch
        let new_db = PassDb::new("hastings1066");
        let key = new_db.key;
        let salt = new_db.salt;

        let passwords = [
            ("title0", "password0"),
            ("title1", "password1"),
            ("title2", "password2"),
        ];
        let mut passwords_vec: Vec<PassEntry> = Vec::new();
        for (password_title, password) in passwords {
            let mut pass_entry = PassEntry::new();
            pass_entry.title = Some(password_title.to_string());
            match pass_entry.save_password(password, &key) {
                Ok(_) => (),
                Err(e) => panic!("Failed to save password due to {:?}", e)
            };
            passwords_vec.push(pass_entry);
        }

        let rebuilt_db = PassDb::rebuild(key, salt, passwords_vec);
        assert_eq!(rebuilt_db.passwords.len(), 3);
        for (i, password) in rebuilt_db.passwords.iter().enumerate() {
            let (original_title, original_password) = passwords[i];
            let saved_title = match &password.title {
                Some(title) => title,
                None => panic!("Title was not saved!")
            };
            assert_eq!(saved_title, original_title);
            let saved_password = match password.get_password(&key) {
                Ok(password) => password.unwrap(),
                Err(e) => panic!("Failed to decrypt password: {:?}", e)
            };
            assert_eq!(saved_password, original_password);
        }
}
}