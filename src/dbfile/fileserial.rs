#[derive(Debug)]
pub enum DbFileWriteError {
    FileCreateError,
    FileWriteError,
}
