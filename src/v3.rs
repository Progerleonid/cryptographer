use std::hint::black_box;

use zeroize::Zeroize;

use crate::{
    MAX_PLAINTEXT_SIZE,
    error::VaultError,
    random::{OsRandom, RandomSource, random_array},
    v2::{self, DecryptedBytes, DecryptedText, ReplayGuard, VaultKey},
    v2_encoding,
    v3_duplex::{authentication_tag, key_commitment, xor_stream},
};

pub const V3_TEXT_PREFIX: &str = "OV3-";
pub const V3_HEADER: [u8; 8] = *b"OBSV3\0\x01\0";
pub const V3_COMMITMENT_SIZE: usize = 16;
pub const V3_NONCE_SIZE: usize = 24;
pub const V3_TAG_SIZE: usize = 32;
pub const V3_PADDING_BLOCK: usize = 32;
pub const V3_INNER_HEADER_SIZE: usize = 8;
pub const V3_MAX_CONTEXT_SIZE: usize = 4_096;
pub const V3_MAX_INNER_SIZE: usize = (V3_INNER_HEADER_SIZE + MAX_PLAINTEXT_SIZE) / V3_PADDING_BLOCK
    * V3_PADDING_BLOCK
    + V3_PADDING_BLOCK;
pub const V3_CONTAINER_OVERHEAD: usize =
    V3_HEADER.len() + V3_COMMITMENT_SIZE + V3_NONCE_SIZE + V3_TAG_SIZE;
pub const V3_MIN_CONTAINER_SIZE: usize = V3_CONTAINER_OVERHEAD + V3_PADDING_BLOCK;
pub const V3_MAX_CONTAINER_SIZE: usize = V3_CONTAINER_OVERHEAD + V3_MAX_INNER_SIZE;
pub const V3_MAX_TEXT_SIZE: usize =
    V3_TEXT_PREFIX.len() + V3_MAX_CONTAINER_SIZE.saturating_mul(4).div_ceil(3);

const INNER_VERSION: u8 = 3;
const INNER_FLAGS: u8 = 0;
const INNER_RESERVED: [u8; 2] = [0; 2];

#[must_use]
pub fn is_v3_container(encoded: &str) -> bool {
    encoded.starts_with(V3_TEXT_PREFIX)
}

fn padded_inner_length(plaintext_length: usize) -> Result<usize, VaultError> {
    let base = V3_INNER_HEADER_SIZE
        .checked_add(plaintext_length)
        .ok_or(VaultError::InputTooLarge)?;
    let padded = base
        .checked_div(V3_PADDING_BLOCK)
        .and_then(|blocks| blocks.checked_add(1))
        .and_then(|blocks| blocks.checked_mul(V3_PADDING_BLOCK))
        .ok_or(VaultError::InputTooLarge)?;
    if plaintext_length > MAX_PLAINTEXT_SIZE || padded > V3_MAX_INNER_SIZE {
        return Err(VaultError::InputTooLarge);
    }
    Ok(padded)
}

fn build_inner(plaintext: &[u8], random: &mut impl RandomSource) -> Result<Vec<u8>, VaultError> {
    let padded_length = padded_inner_length(plaintext.len())?;
    let mut inner = vec![0_u8; padded_length];
    inner[0] = INNER_VERSION;
    inner[1] = INNER_FLAGS;
    inner[2..4].copy_from_slice(&INNER_RESERVED);
    inner[4..8].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    inner[8..8 + plaintext.len()].copy_from_slice(plaintext);
    if let Err(error) = random.fill(&mut inner[8 + plaintext.len()..]) {
        inner.zeroize();
        return Err(error);
    }
    Ok(inner)
}

fn parse_inner(inner: &[u8]) -> Result<Vec<u8>, VaultError> {
    if inner.len() < V3_PADDING_BLOCK
        || inner.len() > V3_MAX_INNER_SIZE
        || inner.len() % V3_PADDING_BLOCK != 0
        || inner[0] != INNER_VERSION
        || inner[1] != INNER_FLAGS
        || inner[2..4] != INNER_RESERVED
    {
        return Err(VaultError::InvalidData);
    }
    let length_bytes: [u8; 4] = inner[4..8]
        .try_into()
        .map_err(|_| VaultError::InvalidData)?;
    let length = u32::from_le_bytes(length_bytes) as usize;
    let expected_padded = padded_inner_length(length).map_err(|_| VaultError::InvalidData)?;
    let end = V3_INNER_HEADER_SIZE
        .checked_add(length)
        .ok_or(VaultError::InvalidData)?;
    if expected_padded != inner.len() || end > inner.len() {
        return Err(VaultError::InvalidData);
    }
    Ok(inner[V3_INNER_HEADER_SIZE..end].to_vec())
}

fn fixed_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    black_box(difference) == 0
}

fn encrypt_with_random(
    plaintext: &[u8],
    key: &VaultKey,
    context: &[u8],
    random: &mut impl RandomSource,
) -> Result<String, VaultError> {
    if context.is_empty() {
        return Err(VaultError::InvalidContext);
    }
    if context.len() > V3_MAX_CONTEXT_SIZE {
        return Err(VaultError::InputTooLarge);
    }
    let nonce: [u8; V3_NONCE_SIZE] = random_array(random)?;
    let commitment = key_commitment(key.as_bytes(), &V3_HEADER, &nonce, context);
    let mut inner = build_inner(plaintext, random)?;
    let tag = authentication_tag(
        key.as_bytes(),
        &V3_HEADER,
        &commitment,
        &nonce,
        context,
        &inner,
    );
    let ciphertext = xor_stream(
        key.as_bytes(),
        &V3_HEADER,
        &commitment,
        &nonce,
        &tag,
        context,
        &inner,
    );
    inner.zeroize();

    let mut container = Vec::with_capacity(V3_CONTAINER_OVERHEAD + ciphertext.len());
    container.extend_from_slice(&V3_HEADER);
    container.extend_from_slice(&commitment);
    container.extend_from_slice(&nonce);
    container.extend_from_slice(&tag);
    container.extend_from_slice(&ciphertext);
    let mut encoded =
        String::with_capacity(V3_TEXT_PREFIX.len() + container.len().saturating_mul(4).div_ceil(3));
    encoded.push_str(V3_TEXT_PREFIX);
    encoded.push_str(&v2_encoding::encode(&container));
    Ok(encoded)
}

pub fn encrypt_bytes(
    plaintext: &[u8],
    key: &VaultKey,
    context: &[u8],
) -> Result<String, VaultError> {
    let mut random = OsRandom;
    encrypt_with_random(plaintext, key, context, &mut random)
}

fn decrypt_v3_bytes_with_token(
    encoded: &str,
    key: &VaultKey,
    context: &[u8],
) -> Result<(DecryptedBytes, [u8; V3_NONCE_SIZE + V3_TAG_SIZE]), VaultError> {
    if context.is_empty() {
        return Err(VaultError::InvalidContext);
    }
    if encoded.len() > V3_MAX_TEXT_SIZE || context.len() > V3_MAX_CONTEXT_SIZE {
        return Err(VaultError::InvalidData);
    }
    let payload = encoded
        .strip_prefix(V3_TEXT_PREFIX)
        .ok_or(VaultError::UnsupportedVersion)?;
    let container = v2_encoding::decode(payload, V3_MAX_CONTAINER_SIZE)?;
    if container.len() < V3_MIN_CONTAINER_SIZE
        || (container.len() - V3_CONTAINER_OVERHEAD) % V3_PADDING_BLOCK != 0
        || container[..V3_HEADER.len()] != V3_HEADER
    {
        return Err(VaultError::InvalidData);
    }

    let commitment_start = V3_HEADER.len();
    let nonce_start = commitment_start + V3_COMMITMENT_SIZE;
    let tag_start = nonce_start + V3_NONCE_SIZE;
    let ciphertext_start = tag_start + V3_TAG_SIZE;
    let commitment: [u8; V3_COMMITMENT_SIZE] = container[commitment_start..nonce_start]
        .try_into()
        .map_err(|_| VaultError::InvalidData)?;
    let nonce: [u8; V3_NONCE_SIZE] = container[nonce_start..tag_start]
        .try_into()
        .map_err(|_| VaultError::InvalidData)?;
    let tag: [u8; V3_TAG_SIZE] = container[tag_start..ciphertext_start]
        .try_into()
        .map_err(|_| VaultError::InvalidData)?;

    let expected_commitment = key_commitment(key.as_bytes(), &V3_HEADER, &nonce, context);
    let commitment_valid = fixed_eq(&commitment, &expected_commitment);
    let mut inner = xor_stream(
        key.as_bytes(),
        &V3_HEADER,
        &commitment,
        &nonce,
        &tag,
        context,
        &container[ciphertext_start..],
    );
    let expected_tag = authentication_tag(
        key.as_bytes(),
        &V3_HEADER,
        &commitment,
        &nonce,
        context,
        &inner,
    );
    let tag_valid = fixed_eq(&tag, &expected_tag);
    if !(commitment_valid & tag_valid) {
        inner.zeroize();
        return Err(VaultError::InvalidData);
    }
    let plaintext = match parse_inner(&inner) {
        Ok(value) => value,
        Err(error) => {
            inner.zeroize();
            return Err(error);
        }
    };
    inner.zeroize();

    let mut replay_token = [0_u8; V3_NONCE_SIZE + V3_TAG_SIZE];
    replay_token[..V3_NONCE_SIZE].copy_from_slice(&nonce);
    replay_token[V3_NONCE_SIZE..].copy_from_slice(&tag);
    Ok((DecryptedBytes(plaintext), replay_token))
}

pub fn decrypt_bytes(
    encoded: &str,
    key: &VaultKey,
    context: &[u8],
) -> Result<DecryptedBytes, VaultError> {
    if is_v3_container(encoded) {
        decrypt_v3_bytes_with_token(encoded, key, context).map(|(plaintext, _)| plaintext)
    } else {
        v2::decrypt_bytes(encoded, key, context)
    }
}

pub fn decrypt_bytes_once(
    encoded: &str,
    key: &VaultKey,
    context: &[u8],
    replay_guard: &mut ReplayGuard,
) -> Result<DecryptedBytes, VaultError> {
    if is_v3_container(encoded) {
        let (plaintext, replay_token) = decrypt_v3_bytes_with_token(encoded, key, context)?;
        replay_guard.record(replay_token)?;
        Ok(plaintext)
    } else {
        v2::decrypt_bytes_once(encoded, key, context, replay_guard)
    }
}

pub fn encrypt_text(plaintext: &str, key: &VaultKey, context: &[u8]) -> Result<String, VaultError> {
    encrypt_bytes(plaintext.as_bytes(), key, context)
}

fn bytes_to_text(decrypted: DecryptedBytes) -> Result<DecryptedText, VaultError> {
    let bytes = decrypted.as_slice().to_vec();
    match String::from_utf8(bytes) {
        Ok(text) => Ok(DecryptedText(text)),
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            Err(VaultError::InvalidData)
        }
    }
}

pub fn decrypt_text(
    encoded: &str,
    key: &VaultKey,
    context: &[u8],
) -> Result<DecryptedText, VaultError> {
    bytes_to_text(decrypt_bytes(encoded, key, context)?)
}

pub fn decrypt_text_once(
    encoded: &str,
    key: &VaultKey,
    context: &[u8],
    replay_guard: &mut ReplayGuard,
) -> Result<DecryptedText, VaultError> {
    bytes_to_text(decrypt_bytes_once(encoded, key, context, replay_guard)?)
}

#[cfg(test)]
mod tests {
    use super::{
        V3_CONTAINER_OVERHEAD, V3_MAX_CONTEXT_SIZE, V3_MAX_INNER_SIZE, V3_TEXT_PREFIX,
        decrypt_bytes, encrypt_with_random, padded_inner_length,
    };
    use crate::{MAX_PLAINTEXT_SIZE, VaultError, VaultKey, random::RandomSource, v2_encoding};

    struct FixedRandom(u8);

    impl RandomSource for FixedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), VaultError> {
            for byte in destination {
                self.0 = self.0.wrapping_mul(33).wrapping_add(17);
                *byte = self.0;
            }
            Ok(())
        }
    }

    #[test]
    fn forced_nonce_reuse_still_uses_different_tags_and_streams() {
        let key = VaultKey::from_bytes([3; 64]);
        let first = encrypt_with_random(
            b"known plaintext AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &key,
            b"context",
            &mut FixedRandom(7),
        )
        .expect("first encryption");
        let second = encrypt_with_random(
            b"other plaintext BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            &key,
            b"context",
            &mut FixedRandom(7),
        )
        .expect("second encryption");
        let first_binary = v2_encoding::decode(&first[V3_TEXT_PREFIX.len()..], usize::MAX)
            .expect("first encoding");
        let second_binary = v2_encoding::decode(&second[V3_TEXT_PREFIX.len()..], usize::MAX)
            .expect("second encoding");
        assert_eq!(&first_binary[24..48], &second_binary[24..48]);
        assert_ne!(&first_binary[48..80], &second_binary[48..80]);
        assert_ne!(&first_binary[80..112], &second_binary[80..112]);
        assert_eq!(
            decrypt_bytes(&first, &key, b"context")
                .expect("decryption")
                .as_slice(),
            b"known plaintext AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
    }

    #[test]
    fn every_plaintext_length_has_random_padding() {
        for length in 0..256 {
            let padded = padded_inner_length(length).expect("valid length");
            assert!(padded > 8 + length);
            assert!((1..=32).contains(&(padded - 8 - length)));
        }
    }

    #[test]
    fn size_boundaries_are_checked_without_overflow() {
        assert_eq!(
            padded_inner_length(MAX_PLAINTEXT_SIZE),
            Ok(V3_MAX_INNER_SIZE)
        );
        assert_eq!(
            padded_inner_length(MAX_PLAINTEXT_SIZE + 1),
            Err(VaultError::InputTooLarge)
        );
        let key = VaultKey::from_bytes([1; 64]);
        assert!(matches!(
            encrypt_with_random(
                b"message",
                &key,
                &vec![0; V3_MAX_CONTEXT_SIZE + 1],
                &mut FixedRandom(1)
            ),
            Err(VaultError::InputTooLarge)
        ));
    }

    #[test]
    fn overhead_constant_matches_layout() {
        assert_eq!(V3_CONTAINER_OVERHEAD, 8 + 16 + 24 + 32);
    }
}
