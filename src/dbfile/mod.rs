pub mod fileparse;
pub mod fileserial;
mod utils;

use std::fs::File;
use std::io::{self, Seek, Write};
use fileserial::DbFileWriteError;
use utils::{CHECKSUM_SIZE_BYTES, calculate_crc32};

/// The file signature bytes, in Big Endian order. The file signature will always be written in
/// Big Endian order
const PWMAN_FILE_SIGNATURE: [u8; 8] = [0x7F, 0x70, 0x77, 0x6D, 0x61, 0x6E, 0x2B, 0x2E];
const LITTLE_ENDIAN_BYTE: u8 = 0;


/// The `DbFileWriter` struct handles the writing of the header and data sections of a pwman file.
/// It can be used to create an entirely new file for writing, or it can be used to write to
/// existing files.
pub struct DbFile {
    filepath: String,
    header_buffer: Vec<u8>
}

impl DbFile {
    /// Create a new file for writing a pwman db to. The header section will be written
    /// automatically after file creation
    pub fn new(filepath: &str) -> Result<(), DbFileWriteError> {
        // Try creating a file first, if file cannot be created we can fail early because
        // it would be useless to write to the buffer
        let file = match File::create(filepath) {
            Ok(file) => file,
            Err(_) => return Err(DbFileWriteError::FileCreateError)
        };

        // Write to a buffer first, then to file
        let mut write_buffer: Vec<u8> = Vec::new();
        DbFile::write_file_signature(&mut write_buffer)?;
        DbFile::write_endianness(&mut write_buffer)?;
        // Ok(writer)
        Ok(())
    }

    fn write_file_signature(writer: &mut dyn Write) -> Result<(), DbFileWriteError> {
        if let Err(_) = bincode::serialize_into(writer, &PWMAN_FILE_SIGNATURE) {
            return Err(DbFileWriteError::FileWriteError);
        };
        Ok(())
    }

    fn write_endianness(writer: &mut dyn Write) -> Result<(), DbFileWriteError> {
       if let Err(_) = bincode::serialize_into(writer, &[LITTLE_ENDIAN_BYTE]) {
            return Err(DbFileWriteError::FileWriteError);
       };
       Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_file() -> Result<(), DbFileWriteError> {
        let test_filepath = "/tmp/testdb.pwman";
        DbFile::new(test_filepath)?;
        Ok(())
    }
}
