use std::io::Write;
use bincode;

#[derive(Debug)]
pub enum DbFileWriteError {
    FileCreateError,
    FileWriteError,
}


pub fn write_data(writer: &mut dyn Write, data: &[u8]) -> Result<(), DbFileWriteError> {
    if let Err(_) = bincode::serialize_into(writer, &data) {
        return Err(DbFileWriteError::FileWriteError);
    };
    Ok(())
}
