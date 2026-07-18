use zeroize::Zeroize;

use crate::v3_permutation::{P1024V3, permute};

const DOMAIN_ALGORITHM: u64 = 0x4f56_3300_0000_0001;
const DOMAIN_MASTER_KEY: u64 = 0x4f56_3300_0000_0002;
const DOMAIN_SUBKEY_LABEL: u64 = 0x4f56_3300_0000_0003;
const DOMAIN_HEADER: u64 = 0x4f56_3300_0000_0004;
const DOMAIN_COMMITMENT: u64 = 0x4f56_3300_0000_0005;
const DOMAIN_NONCE: u64 = 0x4f56_3300_0000_0006;
const DOMAIN_CONTEXT: u64 = 0x4f56_3300_0000_0007;
const DOMAIN_MESSAGE: u64 = 0x4f56_3300_0000_0008;
const DOMAIN_TAG: u64 = 0x4f56_3300_0000_0009;
const DOMAIN_LENGTH: u64 = 0x4f56_3300_0000_000a;
const DOMAIN_FINAL: u64 = 0x4f56_3300_0000_000b;

const ALGORITHM_LABEL: &[u8] = b"OBSIDIAN-P1024-V3-DUPLEX-SIV";
const MAC_LABEL: &[u8] = b"OBSIDIAN-V3-MAC-SUBKEY";
const STREAM_LABEL: &[u8] = b"OBSIDIAN-V3-STREAM-SUBKEY";
const COMMITMENT_LABEL: &[u8] = b"OBSIDIAN-V3-COMMITMENT-SUBKEY";

struct Duplex {
    state: P1024V3,
}

impl Duplex {
    fn new() -> Self {
        Self {
            state: P1024V3::initialized(),
        }
    }

    fn absorb(&mut self, domain: u64, data: &[u8]) {
        let framed_length = 16_usize
            .checked_add(data.len())
            .and_then(|length| length.checked_add(1))
            .expect("allocated slice length fits usize");
        let padded_length = framed_length.div_ceil(64) * 64;
        let mut prefix = [0_u8; 16];
        prefix[..8].copy_from_slice(&domain.to_le_bytes());
        prefix[8..].copy_from_slice(&(data.len() as u64).to_le_bytes());

        for block_index in 0..padded_length / 64 {
            let block_start = block_index * 64;
            let mut block = [0_u8; 64];
            copy_segment(&mut block, block_start, 0, &prefix);
            copy_segment(&mut block, block_start, 16, data);
            let marker = 16 + data.len();
            if (block_start..block_start + 64).contains(&marker) {
                block[marker - block_start] = 0x01;
            }
            if block_index + 1 == padded_length / 64 {
                block[63] ^= 0x80;
            }
            for (lane, bytes) in self
                .state
                .lanes_mut()
                .iter_mut()
                .take(8)
                .zip(block.chunks_exact(8))
            {
                let mut word = [0_u8; 8];
                word.copy_from_slice(bytes);
                *lane ^= u64::from_le_bytes(word);
            }
            self.state.lanes_mut()[8] ^= domain;
            self.state.lanes_mut()[9] ^= (block_index as u64).wrapping_add(1);
            self.state.lanes_mut()[14] ^= (data.len() as u64).rotate_left(17);
            self.state.lanes_mut()[15] ^= !(block_index as u64) ^ domain.rotate_left(31) ^ 0x01_80;
            permute(&mut self.state);
            block.zeroize();
        }
        prefix.zeroize();
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        for (index, chunk) in output.chunks_mut(64).enumerate() {
            if index != 0 {
                permute(&mut self.state);
            }
            let mut rate = [0_u8; 64];
            for (bytes, lane) in rate
                .chunks_exact_mut(8)
                .zip(self.state.lanes().iter().take(8))
            {
                bytes.copy_from_slice(&lane.to_le_bytes());
            }
            chunk.copy_from_slice(&rate[..chunk.len()]);
            rate.zeroize();
        }
    }
}

fn copy_segment(block: &mut [u8; 64], block_start: usize, source_start: usize, source: &[u8]) {
    let block_end = block_start + block.len();
    let source_end = source_start + source.len();
    let start = block_start.max(source_start);
    let end = block_end.min(source_end);
    if start < end {
        block[start - block_start..end - block_start]
            .copy_from_slice(&source[start - source_start..end - source_start]);
    }
}

fn derive_subkey(master_key: &[u8; 64], label: &[u8]) -> [u8; 64] {
    let mut duplex = Duplex::new();
    duplex.absorb(DOMAIN_ALGORITHM, ALGORITHM_LABEL);
    duplex.absorb(DOMAIN_MASTER_KEY, master_key);
    duplex.absorb(DOMAIN_SUBKEY_LABEL, label);
    duplex.absorb(DOMAIN_FINAL, b"derive-subkey");
    let mut output = [0_u8; 64];
    duplex.squeeze(&mut output);
    output
}

fn keyed_duplex(subkey: &[u8; 64], purpose: &[u8]) -> Duplex {
    let mut duplex = Duplex::new();
    duplex.absorb(DOMAIN_ALGORITHM, ALGORITHM_LABEL);
    duplex.absorb(DOMAIN_MASTER_KEY, subkey);
    duplex.absorb(DOMAIN_SUBKEY_LABEL, purpose);
    duplex
}

pub fn key_commitment(
    master_key: &[u8; 64],
    header: &[u8],
    nonce: &[u8; 24],
    context: &[u8],
) -> [u8; 16] {
    let mut subkey = derive_subkey(master_key, COMMITMENT_LABEL);
    let mut duplex = keyed_duplex(&subkey, COMMITMENT_LABEL);
    duplex.absorb(DOMAIN_HEADER, header);
    duplex.absorb(DOMAIN_NONCE, nonce);
    duplex.absorb(DOMAIN_CONTEXT, context);
    duplex.absorb(DOMAIN_FINAL, b"key-commitment");
    let mut commitment = [0_u8; 16];
    duplex.squeeze(&mut commitment);
    subkey.zeroize();
    commitment
}

pub fn authentication_tag(
    master_key: &[u8; 64],
    header: &[u8],
    commitment: &[u8; 16],
    nonce: &[u8; 24],
    context: &[u8],
    message: &[u8],
) -> [u8; 32] {
    let mut subkey = derive_subkey(master_key, MAC_LABEL);
    let mut duplex = keyed_duplex(&subkey, MAC_LABEL);
    duplex.absorb(DOMAIN_HEADER, header);
    duplex.absorb(DOMAIN_COMMITMENT, commitment);
    duplex.absorb(DOMAIN_NONCE, nonce);
    duplex.absorb(DOMAIN_CONTEXT, context);
    duplex.absorb(DOMAIN_LENGTH, &(message.len() as u64).to_le_bytes());
    duplex.absorb(DOMAIN_MESSAGE, message);
    duplex.absorb(DOMAIN_FINAL, b"authentication-tag");
    let mut tag = [0_u8; 32];
    duplex.squeeze(&mut tag);
    subkey.zeroize();
    tag
}

pub fn xor_stream(
    master_key: &[u8; 64],
    header: &[u8],
    commitment: &[u8; 16],
    nonce: &[u8; 24],
    tag: &[u8; 32],
    context: &[u8],
    input: &[u8],
) -> Vec<u8> {
    let mut subkey = derive_subkey(master_key, STREAM_LABEL);
    let mut duplex = keyed_duplex(&subkey, STREAM_LABEL);
    duplex.absorb(DOMAIN_HEADER, header);
    duplex.absorb(DOMAIN_COMMITMENT, commitment);
    duplex.absorb(DOMAIN_NONCE, nonce);
    duplex.absorb(DOMAIN_TAG, tag);
    duplex.absorb(DOMAIN_CONTEXT, context);
    duplex.absorb(DOMAIN_LENGTH, &(input.len() as u64).to_le_bytes());
    duplex.absorb(DOMAIN_FINAL, b"encryption-stream");

    let mut stream = vec![0_u8; input.len()];
    duplex.squeeze(&mut stream);
    for (output, input) in stream.iter_mut().zip(input) {
        *output ^= input;
    }
    subkey.zeroize();
    stream
}

#[cfg(test)]
mod tests {
    use super::{authentication_tag, key_commitment, xor_stream};

    #[test]
    fn purposes_are_separated_and_stream_is_reversible() {
        let key = [7_u8; 64];
        let nonce = [9_u8; 24];
        let header = b"header";
        let commitment = key_commitment(&key, header, &nonce, b"context");
        let tag = authentication_tag(&key, header, &commitment, &nonce, b"context", b"message");
        assert_ne!(&commitment[..], &tag[..16]);
        let encrypted = xor_stream(
            &key,
            header,
            &commitment,
            &nonce,
            &tag,
            b"context",
            b"message",
        );
        assert_eq!(
            xor_stream(
                &key,
                header,
                &commitment,
                &nonce,
                &tag,
                b"context",
                &encrypted,
            ),
            b"message"
        );
    }
}
