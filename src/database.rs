//! This module provides the functionality for the password database

use std::collections::HashMap;

pub struct PasswordDb {
    key: Option<[u8; 32]>,
    salt: String,
    // Placeholder first, replace with a better datastructure
    passwords: HashMap<u32, String>,
}
