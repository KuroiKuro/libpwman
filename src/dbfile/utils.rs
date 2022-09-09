use crc::{Crc, CRC_32_CKSUM};

pub const CHECKSUM_SIZE_BYTES: u8 = 4;
const CRC32_CKSUM_ALG: Crc<u32> = Crc::<u32>::new(&CRC_32_CKSUM);


pub fn calculate_crc32(data: &[u8]) -> u32 {
    let mut digest = CRC32_CKSUM_ALG.digest();
    digest.update(data);
    digest.finalize()
}
