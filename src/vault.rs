use zeroize::Zeroize;

use crate::{
    container::{TAG_SIZE, parse_container},
    encoding::{decode_container, decode_key},
    error::VaultError,
    padding::parse_inner_block,
    permutation::{ObsidianState, permute},
    sponge::{
        DOMAIN_BLOCK_INDEX, DOMAIN_CIPHERTEXT_BLOCK, DOMAIN_CIPHERTEXT_LENGTH, DOMAIN_FINAL_TAG,
        DOMAIN_HEADER, DOMAIN_LAST_BLOCK, absorb, initialize_session, squeeze,
    },
};

const FINAL_TAG_LABEL: &[u8] = b"OBSIDIAN-FINAL-TAG-V1";

struct SecretKey([u8; 96]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct DecryptedText(String);

impl DecryptedText {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for DecryptedText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn process_blocks(state: &mut ObsidianState, input: &[u8], decrypting: bool) -> (Vec<u8>, u64) {
    let mut output = Vec::with_capacity(input.len());
    let mut last_index = 0_u64;
    for (index, block) in input.chunks(64).enumerate() {
        last_index = index as u64;
        absorb(state, DOMAIN_BLOCK_INDEX, &last_index.to_le_bytes());
        permute(state, 24);
        let mut stream = [0_u8; 64];
        squeeze(state, &mut stream);
        let output_start = output.len();
        output.extend(
            block
                .iter()
                .zip(stream.iter())
                .map(|(value, key)| value ^ key),
        );
        let ciphertext = if decrypting {
            block
        } else {
            &output[output_start..]
        };
        absorb(state, DOMAIN_CIPHERTEXT_BLOCK, ciphertext);
        permute(state, 12);
        stream.zeroize();
    }
    (output, last_index)
}

fn finalize_tag(
    state: &mut ObsidianState,
    ciphertext_length: usize,
    header: &[u8],
    last_block: u64,
) -> [u8; TAG_SIZE] {
    absorb(
        state,
        DOMAIN_CIPHERTEXT_LENGTH,
        &(ciphertext_length as u64).to_le_bytes(),
    );
    absorb(state, DOMAIN_HEADER, header);
    absorb(state, DOMAIN_LAST_BLOCK, &last_block.to_le_bytes());
    absorb(state, DOMAIN_FINAL_TAG, FINAL_TAG_LABEL);
    permute(state, 48);
    let mut tag = [0_u8; TAG_SIZE];
    squeeze(state, &mut tag);
    permute(state, 24);
    tag
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let iterations = a.len().max(b.len());
    let mut difference = a.len() ^ b.len();
    for index in 0..iterations {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

pub fn decrypt_text(
    encoded_container: &str,
    encoded_key: &str,
) -> Result<DecryptedText, VaultError> {
    let binary = decode_container(encoded_container)?;
    let container = parse_container(&binary)?;
    let key = SecretKey(decode_key(encoded_key)?);
    let mut state = initialize_session(&key.0, &container.salt, &container.nonce);
    let (mut inner, last_block) = process_blocks(&mut state, container.ciphertext, true);
    let expected_tag = finalize_tag(
        &mut state,
        container.ciphertext.len(),
        container.header,
        last_block,
    );
    if !constant_time_eq(&expected_tag, &container.tag) {
        inner.zeroize();
        return Err(VaultError::InvalidData);
    }

    let mut plaintext = match parse_inner_block(&inner) {
        Ok(value) => value,
        Err(error) => {
            inner.zeroize();
            return Err(error);
        }
    };
    inner.zeroize();
    match String::from_utf8(plaintext) {
        Ok(text) => Ok(DecryptedText(text)),
        Err(error) => {
            plaintext = error.into_bytes();
            plaintext.zeroize();
            Err(VaultError::InvalidData)
        }
    }
}
