//! This module provides the functionality for the password manager

use crate::pwdb::passentry::{PassEntry, PasswordEntry};

/// A handler type that handles saving and retrieving of the various password entries.
///
/// Encapsulating this behaviour in this type allows for flexibility when working with the
/// password database file, such as allowing either loading all the passwords from the file into
/// memory, or to allow reading of the password data of a specific entry from the database file
/// on demand.
pub struct PassEntryManager<T: PasswordEntry> {
    entries: Vec<T>,
}

impl PassEntryManager<PassEntry> {
    pub fn new() -> PassEntryManager<PassEntry> {
        PassEntryManager { entries: Vec::new() }
    }

    pub fn set_entries(&mut self, entries: Vec<PassEntry>) {
        self.entries = entries;
    }
}

pub trait PasswordEntryManager {
    type PasswordEntryType;

    fn get_all_entries(&self) -> Vec<Self::PasswordEntryType>;
    fn filter_by_title(&self, search_value: &str, case_sensitive: bool) -> Vec<&Self::PasswordEntryType>;
}

impl PasswordEntryManager for PassEntryManager<PassEntry> {
    type PasswordEntryType = PassEntry;

    fn get_all_entries(&self) -> Vec<Self::PasswordEntryType> {
        self.entries.to_vec()
    }

    fn filter_by_title(&self, search_value: &str, case_sensitive: bool) -> Vec<&Self::PasswordEntryType>{
        let mut ret_vec: Vec<&Self::PasswordEntryType> = Vec::new();
        for entry in &self.entries {
            let title = match &entry.title {
                Some(title) => title,
                None => continue
            };
            let title = String::from(title);

            let title_to_search = if !case_sensitive {
                title.to_lowercase()
            } else {title};

            if title_to_search.contains(search_value) {
                ret_vec.push(&entry);
            }
        }
        ret_vec
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::{generate_salt, get_key_bytes_from_pw, Aes256KeyBytes, SaltString};
    use crate::pwdb::{PassEntry, PasswordEntry};

    fn create_key() -> (Aes256KeyBytes, SaltString) {
        let db_password = "password";
        let salt = generate_salt();
        let key = get_key_bytes_from_pw(db_password, &salt);
        (key, salt)
    }

    // #[test]
    // fn test_get_all_entries() {
    //     let password1 = PassEntry::new();
    //     password1.title = "title1";
    //     password1.save_password("password1", enc_key)
    // }
}
