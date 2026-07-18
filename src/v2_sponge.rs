use zeroize::Zeroize;

use crate::v2_permutation::{P1024V2, permute};

const DOMAIN_ALGORITHM: u64 = 0x5632_0000_0000_0001;
const DOMAIN_MASTER_KEY: u64 = 0x5632_0000_0000_0002;
const DOMAIN_SUBKEY_LABEL: u64 = 0x5632_0000_0000_0003;
const DOMAIN_NONCE: u64 = 0x5632_0000_0000_0004;
const DOMAIN_CONTEXT: u64 = 0x5632_0000_0000_0005;
const DOMAIN_MESSAGE: u64 = 0x5632_0000_0000_0006;
const DOMAIN_TAG: u64 = 0x5632_0000_0000_0007;
const DOMAIN_LENGTH: u64 = 0x5632_0000_0000_0008;
const DOMAIN_FINAL: u64 = 0x5632_0000_0000_0009;

const ALGORITHM_LABEL: &[u8] = b"OBSIDIAN-P1024-V2-SIV";
const MAC_LABEL: &[u8] = b"OBSIDIAN-V2-MAC-SUBKEY";
const STREAM_LABEL: &[u8] = b"OBSIDIAN-V2-STREAM-SUBKEY";

fn absorb(state: &mut P1024V2, domain: u64, data: &[u8]) {
    let framed_length = 16_usize
        .checked_add(data.len())
        .and_then(|length| length.checked_add(1))
        .expect("slice length fits usize");
    let padded_length = framed_length.div_ceil(64) * 64;
    let mut framed = vec![0_u8; padded_length];
    framed[..8].copy_from_slice(&domain.to_le_bytes());
    framed[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());
    framed[16..16 + data.len()].copy_from_slice(data);
    framed[16 + data.len()] = 0x01;
    if let Some(last) = framed.last_mut() {
        *last ^= 0x80;
    }

    for (block_index, block) in framed.chunks_exact(64).enumerate() {
        for (lane, bytes) in state
            .lanes_mut()
            .iter_mut()
            .take(8)
            .zip(block.chunks_exact(8))
        {
            let mut word = [0_u8; 8];
            word.copy_from_slice(bytes);
            *lane ^= u64::from_le_bytes(word);
        }
        state.lanes_mut()[8] ^= domain;
        state.lanes_mut()[9] ^= (block_index as u64).wrapping_add(1);
        state.lanes_mut()[15] ^= !(block_index as u64) ^ domain.rotate_left(29);
        permute(state);
    }
    framed.zeroize();
}

fn squeeze(state: &mut P1024V2, output: &mut [u8]) {
    for (index, chunk) in output.chunks_mut(64).enumerate() {
        if index != 0 {
            permute(state);
        }
        let mut rate = [0_u8; 64];
        for (bytes, lane) in rate.chunks_exact_mut(8).zip(state.lanes().iter().take(8)) {
            bytes.copy_from_slice(&lane.to_le_bytes());
        }
        chunk.copy_from_slice(&rate[..chunk.len()]);
        rate.zeroize();
    }
}

fn keyed_state(key: &[u8; 64], purpose: &[u8]) -> P1024V2 {
    let mut state = P1024V2::initialized();
    absorb(&mut state, DOMAIN_ALGORITHM, ALGORITHM_LABEL);
    absorb(&mut state, DOMAIN_MASTER_KEY, key);
    absorb(&mut state, DOMAIN_SUBKEY_LABEL, purpose);
    absorb(&mut state, DOMAIN_FINAL, b"derive");
    state
}

fn derive_subkey(master_key: &[u8; 64], label: &[u8]) -> [u8; 64] {
    let mut state = keyed_state(master_key, label);
    let mut output = [0_u8; 64];
    squeeze(&mut state, &mut output);
    output
}

pub fn authentication_tag(
    master_key: &[u8; 64],
    nonce: &[u8; 24],
    context: &[u8],
    message: &[u8],
) -> [u8; 32] {
    let mut mac_key = derive_subkey(master_key, MAC_LABEL);
    let mut state = keyed_state(&mac_key, MAC_LABEL);
    absorb(&mut state, DOMAIN_NONCE, nonce);
    absorb(&mut state, DOMAIN_CONTEXT, context);
    absorb(&mut state, DOMAIN_MESSAGE, message);
    absorb(&mut state, DOMAIN_FINAL, b"tag");
    let mut tag = [0_u8; 32];
    squeeze(&mut state, &mut tag);
    mac_key.zeroize();
    tag
}

pub fn xor_stream(
    master_key: &[u8; 64],
    nonce: &[u8; 24],
    tag: &[u8; 32],
    context: &[u8],
    input: &[u8],
) -> Vec<u8> {
    let mut stream_key = derive_subkey(master_key, STREAM_LABEL);
    let mut state = keyed_state(&stream_key, STREAM_LABEL);
    absorb(&mut state, DOMAIN_NONCE, nonce);
    absorb(&mut state, DOMAIN_TAG, tag);
    absorb(&mut state, DOMAIN_CONTEXT, context);
    absorb(
        &mut state,
        DOMAIN_LENGTH,
        &(input.len() as u64).to_le_bytes(),
    );
    absorb(&mut state, DOMAIN_FINAL, b"stream");

    let mut output = Vec::with_capacity(input.len());
    for chunk in input.chunks(64) {
        let mut rate = [0_u8; 64];
        squeeze(&mut state, &mut rate[..chunk.len()]);
        output.extend(
            chunk
                .iter()
                .zip(rate.iter())
                .map(|(value, mask)| value ^ mask),
        );
        rate.zeroize();
        if output.len() < input.len() {
            permute(&mut state);
        }
    }
    stream_key.zeroize();
    output
}

#[cfg(test)]
mod tests {
    use super::{authentication_tag, xor_stream};

    #[test]
    fn stream_is_reversible() {
        let key = [7_u8; 64];
        let nonce = [9_u8; 24];
        let tag = authentication_tag(&key, &nonce, b"context", b"message");
        let encrypted = xor_stream(&key, &nonce, &tag, b"context", b"message");
        assert_eq!(
            xor_stream(&key, &nonce, &tag, b"context", &encrypted),
            b"message"
        );
    }

    #[test]
    fn fixed_mac_and_stream_vectors() {
        let key = [7_u8; 64];
        let nonce = [9_u8; 24];
        let tag = authentication_tag(&key, &nonce, b"context", b"message");
        assert_eq!(
            tag,
            [
                0x9a, 0x7f, 0x2f, 0x08, 0x7c, 0x98, 0x97, 0x42, 0xde, 0xd8, 0x53, 0x5b, 0xb6, 0x3b,
                0xc0, 0xfb, 0xe6, 0x7d, 0x3b, 0xed, 0x0a, 0x9a, 0x57, 0x2f, 0xe5, 0xbc, 0xb2, 0xce,
                0x7b, 0x20, 0x41, 0x35,
            ]
        );
        assert_eq!(
            xor_stream(&key, &nonce, &tag, b"context", &[0_u8; 32]),
            [
                0xbb, 0x80, 0x61, 0xda, 0x2a, 0x80, 0x45, 0x50, 0x60, 0x5f, 0x93, 0xf8, 0xb2, 0x6c,
                0x98, 0x9b, 0xbe, 0x1e, 0x20, 0x01, 0x9d, 0x61, 0x34, 0x2a, 0x9a, 0x7a, 0xca, 0xaa,
                0xf0, 0xc0, 0x83, 0xf1,
            ]
        );
    }
}
