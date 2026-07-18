use crate::{MAX_CIPHERTEXT_SIZE, MAX_CONTAINER_SIZE, error::VaultError};

pub const MAGIC: &[u8; 8] = b"OBSVLT01";
pub const VERSION: u8 = 0x01;
pub const ALGORITHM_ID: u8 = 0xa1;
pub const HEADER_SIZE: usize = 88;
pub const TAG_SIZE: usize = 32;
pub const MIN_CONTAINER_SIZE: usize = HEADER_SIZE + 512 + TAG_SIZE;

pub struct ContainerView<'a> {
    pub header: &'a [u8],
    pub salt: [u8; 32],
    pub nonce: [u8; 32],
    pub ciphertext: &'a [u8],
    pub tag: [u8; TAG_SIZE],
}

pub fn parse_container(data: &[u8]) -> Result<ContainerView<'_>, VaultError> {
    if data.len() < 9 {
        return Err(VaultError::InvalidData);
    }
    if data.get(..8) != Some(MAGIC.as_slice()) {
        return Err(VaultError::InvalidData);
    }
    if data[8] != VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    if data.len() < MIN_CONTAINER_SIZE || data.len() > MAX_CONTAINER_SIZE {
        return Err(VaultError::InvalidData);
    }
    if data[9] != ALGORITHM_ID
        || data.get(10..12) != Some(&[0_u8; 2])
        || data.get(12..16) != Some(&[0_u8; 4])
    {
        return Err(VaultError::InvalidData);
    }

    let length_bytes: [u8; 8] = data
        .get(80..88)
        .and_then(|value| value.try_into().ok())
        .ok_or(VaultError::InvalidData)?;
    let declared_u64 = u64::from_le_bytes(length_bytes);
    let declared = usize::try_from(declared_u64).map_err(|_| VaultError::InvalidData)?;
    if !(512..=MAX_CIPHERTEXT_SIZE).contains(&declared) || declared % 512 != 0 {
        return Err(VaultError::InvalidData);
    }
    let tag_offset = HEADER_SIZE
        .checked_add(declared)
        .ok_or(VaultError::InvalidData)?;
    let expected_length = tag_offset
        .checked_add(TAG_SIZE)
        .ok_or(VaultError::InvalidData)?;
    if expected_length != data.len() {
        return Err(VaultError::InvalidData);
    }

    let salt: [u8; 32] = data[16..48]
        .try_into()
        .map_err(|_| VaultError::InvalidData)?;
    let nonce: [u8; 32] = data[48..80]
        .try_into()
        .map_err(|_| VaultError::InvalidData)?;
    let tag: [u8; TAG_SIZE] = data[tag_offset..expected_length]
        .try_into()
        .map_err(|_| VaultError::InvalidData)?;
    Ok(ContainerView {
        header: &data[..HEADER_SIZE],
        salt,
        nonce,
        ciphertext: &data[HEADER_SIZE..tag_offset],
        tag,
    })
}
