use std::io::Write;

#[derive(Debug)]
pub enum DbFileWriteError {
    FileCreateError,
    FileWriteError,
}


pub fn write_data(writer: &mut dyn Write, data: &[u8]) -> Result<(), DbFileWriteError> {
    let little_endian_data = data.reverse();
    match writer.write_all(data) {
        Ok(_) => Ok(()),
        Err(_) => Err(DbFileWriteError::FileWriteError)
    }
}
