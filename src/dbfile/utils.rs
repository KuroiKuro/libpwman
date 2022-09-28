use crc::{Crc, CRC_32_CKSUM};

pub const CHECKSUM_SIZE_BYTES: u8 = 4;
const CRC32_CKSUM_ALG: Crc<u32> = Crc::<u32>::new(&CRC_32_CKSUM);

/// Calculates the crc32 checksum of a slice of bytes
pub fn calculate_crc32(data: &[u8]) -> u32 {
    let mut digest = CRC32_CKSUM_ALG.digest();
    digest.update(data);
    digest.finalize()
}

pub fn initialize_vec(v: &mut Vec<u8>, value: u8, iterations: usize) -> &Vec<u8> {
    for _ in 0..iterations {
        v.push(value);
    }
    v
}
