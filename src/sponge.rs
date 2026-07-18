use zeroize::Zeroize;

use crate::permutation::{ObsidianState, permute};

pub const DOMAIN_VERSION: u64 = 0x01;
pub const DOMAIN_KEY: u64 = 0x02;
pub const DOMAIN_SALT: u64 = 0x03;
pub const DOMAIN_NONCE: u64 = 0x04;
pub const DOMAIN_PARAMETERS: u64 = 0x05;
pub const DOMAIN_BLOCK_INDEX: u64 = 0x06;
pub const DOMAIN_CIPHERTEXT_BLOCK: u64 = 0x07;
pub const DOMAIN_CIPHERTEXT_LENGTH: u64 = 0x08;
pub const DOMAIN_HEADER: u64 = 0x09;
pub const DOMAIN_LAST_BLOCK: u64 = 0x0a;
pub const DOMAIN_FINAL_TAG: u64 = 0x0b;

const ALGORITHM_MAGIC: u64 = 0x4f42_5349_4449_414e;
const VERSION_LABEL: &[u8] = b"OBSIDIAN-VAULT-P1024-V1";
const FORMAT_PARAMETERS: [u8; 12] = [1, 0xa1, 64, 0, 64, 0, 32, 0, 0, 2, 0, 0];

pub fn absorb(state: &mut ObsidianState, domain: u64, data: &[u8]) {
    let mut padded = Vec::with_capacity((data.len() + 73).div_ceil(64) * 64);
    padded.extend_from_slice(&(data.len() as u64).to_le_bytes());
    padded.extend_from_slice(data);
    padded.push(0x01);
    let padded_length = padded.len().div_ceil(64) * 64;
    padded.resize(padded_length, 0);
    if let Some(last) = padded.last_mut() {
        *last ^= 0x80;
    }

    for (block_index, block) in padded.chunks_exact(64).enumerate() {
        let lanes = state.lanes_mut();
        for (lane, block_bytes) in lanes.iter_mut().take(8).zip(block.chunks_exact(8)) {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(block_bytes);
            *lane ^= u64::from_le_bytes(bytes);
        }
        lanes[8] ^= domain;
        lanes[9] ^= (block_index as u64).wrapping_add(1);
        lanes[15] ^= domain.rotate_left(32) ^ !(block_index as u64);
        permute(state, 24);
    }
    padded.zeroize();
}

pub fn squeeze(state: &mut ObsidianState, output: &mut [u8]) {
    for (chunk_index, chunk) in output.chunks_mut(64).enumerate() {
        if chunk_index != 0 {
            permute(state, 24);
        }
        let mut rate = [0_u8; 64];
        for (destination, lane) in rate.chunks_exact_mut(8).zip(state.lanes().iter().take(8)) {
            destination.copy_from_slice(&lane.to_le_bytes());
        }
        chunk.copy_from_slice(&rate[..chunk.len()]);
        rate.zeroize();
    }
}

#[must_use]
pub fn initialize_session(
    master_key: &[u8; 96],
    salt: &[u8; 32],
    nonce: &[u8; 32],
) -> ObsidianState {
    let mut state = ObsidianState::initialized();
    state.lanes_mut()[15] ^= ALGORITHM_MAGIC;
    absorb(&mut state, DOMAIN_VERSION, VERSION_LABEL);
    absorb(&mut state, DOMAIN_KEY, master_key);
    permute(&mut state, 48);
    absorb(&mut state, DOMAIN_SALT, salt);
    permute(&mut state, 24);
    absorb(&mut state, DOMAIN_NONCE, nonce);
    permute(&mut state, 24);
    absorb(&mut state, DOMAIN_PARAMETERS, &FORMAT_PARAMETERS);
    permute(&mut state, 24);
    state
}
