//! This module provides the functionality for the password database. It contains functionality
//! related to password entries, managing entries and the password database.

mod passdb;
mod passentry;
mod passmanager;

pub use passdb::*;
pub use passentry::*;
pub use passmanager::*;