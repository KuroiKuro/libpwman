use crc::{Crc, CRC_32_CKSUM};
use rand::RngCore;
use rand::rngs::OsRng;

pub const CHECKSUM_SIZE_BYTES: u8 = 4;
const CRC32_CKSUM_ALG: Crc<u32> = Crc::<u32>::new(&CRC_32_CKSUM);

/// Calculates the crc32 checksum of a slice of bytes
pub fn calculate_crc32(data: &[u8]) -> u32 {
    let mut digest = CRC32_CKSUM_ALG.digest();
    digest.update(data);
    digest.finalize()
}

/// Generates a random plaintext data slice, for use in the db file header. The plaintext will
/// be encrypted and the resulting ciphertext can be used to test if a user has entered a correct
/// password. If the password is correct, the decrypted ciphertext should match the plaintext.
/// The generated plaintext is not actually text, just a sequence of bytes. It is generated with
/// the `OsRng` struct from the `rand` crate
pub fn generate_plaintext_check(plaintext_length: usize) -> Vec<u8> {
    let mut plaintext: Vec<u8> = vec![0; plaintext_length];
    let mut rng = OsRng::default();
    rng.fill_bytes(&mut plaintext);
    plaintext
}
