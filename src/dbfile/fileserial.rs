use std::io::Write;

#[derive(Debug)]
pub enum DbFileWriteError {
    FileCreateError,
    FileWriteError,
}

/// Helper function to write data from a buffer into a type that implements the `Write` trait.
/// If the `convert_le` argument is set to `true`, then the function will treat the data that
/// was written as if it is in Big Endian format, and thus reverse the data before writing it
pub fn write_data(writer: &mut dyn Write, data: &[u8], convert_le: bool) -> Result<(), DbFileWriteError> {
    // TODO: Write this in a more efficient manner!
    let mut data_to_write: Vec<u8> = Vec::with_capacity(data.len());
    for data_byte in data {
        data_to_write.push(*data_byte);
    }
    if convert_le {
        data_to_write.reverse();
    }
    match writer.write_all(&data_to_write) {
        Ok(_) => Ok(()),
        Err(_) => Err(DbFileWriteError::FileWriteError)
    }
}
