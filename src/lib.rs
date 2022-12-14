//! libpwman - The library crate for pwman
//!
//! Provides the actual functionality of the pwman password manager hobby project.

pub mod crypt;
pub mod keys;
pub mod pwdb;
pub mod dbfile;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
