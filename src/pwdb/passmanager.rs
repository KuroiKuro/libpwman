//! This module provides the functionality for the password manager

use crate::pwdb::passentry::PasswordEntry;

/// A handler type that handles saving and retrieving of the various password entries.
/// 
/// Encapsulating this behaviour in this type allows for flexibility when working with the
/// password database file, such as allowing either loading all the passwords from the file into
/// memory, or to allow reading of the password data of a specific entry from the database file
/// on demand.
pub struct PassEntryManager<T: PasswordEntry> {
    entries: Vec<T>
}

pub trait PasswordEntryManager {
    type PasswordEntryType;

    fn get_all_entries(&self) -> Vec<Self::PasswordEntryType>;
    fn filter_by_field(&self, field_name: &str, field_value: &str);
}
