use crate::{MAX_CIPHERTEXT_SIZE, MAX_PLAINTEXT_SIZE, error::VaultError};

pub const PADDING_BLOCK_SIZE: usize = 512;
const METADATA_SIZE: usize = 32;

pub fn parse_inner_block(block: &[u8]) -> Result<Vec<u8>, VaultError> {
    if block.len() < PADDING_BLOCK_SIZE
        || block.len() > MAX_CIPHERTEXT_SIZE
        || block.len() % PADDING_BLOCK_SIZE != 0
    {
        return Err(VaultError::InvalidData);
    }
    let length_bytes: [u8; 8] = block
        .get(..8)
        .and_then(|value| value.try_into().ok())
        .ok_or(VaultError::InvalidData)?;
    let inverse_bytes: [u8; 8] = block
        .get(8..16)
        .and_then(|value| value.try_into().ok())
        .ok_or(VaultError::InvalidData)?;
    let declared = u64::from_le_bytes(length_bytes);
    if !declared != u64::from_le_bytes(inverse_bytes) {
        return Err(VaultError::InvalidData);
    }
    let length = usize::try_from(declared).map_err(|_| VaultError::InvalidData)?;
    if length > MAX_PLAINTEXT_SIZE {
        return Err(VaultError::InvalidData);
    }
    let text_end = METADATA_SIZE
        .checked_add(length)
        .ok_or(VaultError::InvalidData)?;
    let marker_end = text_end.checked_add(1).ok_or(VaultError::InvalidData)?;
    if marker_end > block.len() || block.get(text_end) != Some(&0x80) {
        return Err(VaultError::InvalidData);
    }
    Ok(block[METADATA_SIZE..text_end].to_vec())
}
