use std::{collections::HashSet, hint::black_box};

use zeroize::Zeroize;

use crate::{
    MAX_PLAINTEXT_SIZE,
    error::VaultError,
    random::{OsRandom, random_array},
    v2_encoding,
    v2_sponge::{authentication_tag, xor_stream},
};

#[cfg(test)]
use crate::random::RandomSource;

pub const V2_KEY_SIZE: usize = 64;
pub const V2_NONCE_SIZE: usize = 24;
pub const V2_TAG_SIZE: usize = 32;
pub const V2_PADDING_BLOCK: usize = 32;
pub const V2_INNER_HEADER_SIZE: usize = 6;
pub const V2_MAX_CONTEXT_SIZE: usize = 4_096;
pub const V2_MIN_CONTAINER_SIZE: usize = V2_NONCE_SIZE + V2_TAG_SIZE + V2_PADDING_BLOCK;
pub const V2_MAX_INNER_SIZE: usize =
    (V2_INNER_HEADER_SIZE + MAX_PLAINTEXT_SIZE).div_ceil(V2_PADDING_BLOCK) * V2_PADDING_BLOCK;
pub const V2_MAX_CONTAINER_SIZE: usize = V2_NONCE_SIZE + V2_TAG_SIZE + V2_MAX_INNER_SIZE;
pub const V2_MAX_TEXT_SIZE: usize = V2_MAX_CONTAINER_SIZE.saturating_mul(4).div_ceil(3);
const V2_REPLAY_TOKEN_SIZE: usize = V2_NONCE_SIZE + V2_TAG_SIZE;

const INNER_VERSION: u8 = 2;
const INNER_FLAGS: u8 = 0;

pub struct VaultKey([u8; V2_KEY_SIZE]);

impl VaultKey {
    pub fn generate() -> Result<Self, VaultError> {
        let mut random = OsRandom;
        Ok(Self(random_array(&mut random)?))
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; V2_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; V2_KEY_SIZE] {
        &self.0
    }
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Bounded in-memory replay state for one key and context domain.
pub struct ReplayGuard {
    maximum_entries: usize,
    seen: HashSet<[u8; V2_REPLAY_TOKEN_SIZE]>,
}

impl ReplayGuard {
    #[must_use]
    pub fn new(maximum_entries: usize) -> Self {
        Self {
            maximum_entries,
            seen: HashSet::with_capacity(maximum_entries),
        }
    }

    pub(crate) fn record(&mut self, token: [u8; V2_REPLAY_TOKEN_SIZE]) -> Result<(), VaultError> {
        if self.seen.contains(&token) {
            return Err(VaultError::ReplayDetected);
        }
        if self.seen.len() >= self.maximum_entries {
            return Err(VaultError::ReplayWindowFull);
        }
        self.seen.insert(token);
        Ok(())
    }
}

pub struct DecryptedBytes(pub(crate) Vec<u8>);

impl DecryptedBytes {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for DecryptedBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct DecryptedText(pub(crate) String);

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

fn padded_inner_length(plaintext_length: usize) -> Result<usize, VaultError> {
    let base = V2_INNER_HEADER_SIZE
        .checked_add(plaintext_length)
        .ok_or(VaultError::InputTooLarge)?;
    let padded = base
        .checked_add(V2_PADDING_BLOCK - 1)
        .map(|length| length / V2_PADDING_BLOCK * V2_PADDING_BLOCK)
        .ok_or(VaultError::InputTooLarge)?;
    if plaintext_length > MAX_PLAINTEXT_SIZE || padded > V2_MAX_INNER_SIZE {
        return Err(VaultError::InputTooLarge);
    }
    Ok(padded)
}

#[cfg(test)]
fn build_inner(plaintext: &[u8], random: &mut impl RandomSource) -> Result<Vec<u8>, VaultError> {
    let padded_length = padded_inner_length(plaintext.len())?;
    let mut inner = vec![0_u8; padded_length];
    inner[0] = INNER_VERSION;
    inner[1] = INNER_FLAGS;
    inner[2..6].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    inner[6..6 + plaintext.len()].copy_from_slice(plaintext);
    if let Err(error) = random.fill(&mut inner[6 + plaintext.len()..]) {
        inner.zeroize();
        return Err(error);
    }
    Ok(inner)
}

fn parse_inner(inner: &[u8]) -> Result<Vec<u8>, VaultError> {
    if inner.len() < V2_PADDING_BLOCK
        || inner.len() > V2_MAX_INNER_SIZE
        || inner.len() % V2_PADDING_BLOCK != 0
        || inner[0] != INNER_VERSION
        || inner[1] != INNER_FLAGS
    {
        return Err(VaultError::InvalidData);
    }
    let length_bytes: [u8; 4] = inner[2..6]
        .try_into()
        .map_err(|_| VaultError::InvalidData)?;
    let length =
        usize::try_from(u32::from_le_bytes(length_bytes)).map_err(|_| VaultError::InvalidData)?;
    let expected_padded = padded_inner_length(length).map_err(|_| VaultError::InvalidData)?;
    let end = V2_INNER_HEADER_SIZE
        .checked_add(length)
        .ok_or(VaultError::InvalidData)?;
    if expected_padded != inner.len() || end > inner.len() {
        return Err(VaultError::InvalidData);
    }
    Ok(inner[V2_INNER_HEADER_SIZE..end].to_vec())
}

fn fixed_tag_eq(left: &[u8; V2_TAG_SIZE], right: &[u8; V2_TAG_SIZE]) -> bool {
    let mut difference = 0_u8;
    for index in 0..V2_TAG_SIZE {
        difference |= left[index] ^ right[index];
    }
    black_box(difference) == 0
}

#[cfg(test)]
fn encrypt_with_random(
    plaintext: &[u8],
    key: &VaultKey,
    context: &[u8],
    random: &mut impl RandomSource,
) -> Result<String, VaultError> {
    if context.is_empty() {
        return Err(VaultError::InvalidContext);
    }
    if context.len() > V2_MAX_CONTEXT_SIZE {
        return Err(VaultError::InputTooLarge);
    }
    let nonce = random_array(random)?;
    let mut inner = build_inner(plaintext, random)?;
    let tag = authentication_tag(key.as_bytes(), &nonce, context, &inner);
    let ciphertext = xor_stream(key.as_bytes(), &nonce, &tag, context, &inner);
    inner.zeroize();

    let mut container = Vec::with_capacity(V2_NONCE_SIZE + V2_TAG_SIZE + ciphertext.len());
    container.extend_from_slice(&nonce);
    container.extend_from_slice(&tag);
    container.extend_from_slice(&ciphertext);
    Ok(v2_encoding::encode(&container))
}

fn decrypt_bytes_with_token(
    encoded: &str,
    key: &VaultKey,
    context: &[u8],
) -> Result<(DecryptedBytes, [u8; V2_REPLAY_TOKEN_SIZE]), VaultError> {
    if context.is_empty() {
        return Err(VaultError::InvalidContext);
    }
    if encoded.len() > V2_MAX_TEXT_SIZE || context.len() > V2_MAX_CONTEXT_SIZE {
        return Err(VaultError::InvalidData);
    }
    let container = v2_encoding::decode(encoded, V2_MAX_CONTAINER_SIZE)?;
    if container.len() < V2_MIN_CONTAINER_SIZE
        || (container.len() - V2_NONCE_SIZE - V2_TAG_SIZE) % V2_PADDING_BLOCK != 0
    {
        return Err(VaultError::InvalidData);
    }
    let nonce: [u8; V2_NONCE_SIZE] = container[..V2_NONCE_SIZE]
        .try_into()
        .map_err(|_| VaultError::InvalidData)?;
    let tag: [u8; V2_TAG_SIZE] = container[V2_NONCE_SIZE..V2_NONCE_SIZE + V2_TAG_SIZE]
        .try_into()
        .map_err(|_| VaultError::InvalidData)?;
    let mut replay_token = [0_u8; V2_REPLAY_TOKEN_SIZE];
    replay_token[..V2_NONCE_SIZE].copy_from_slice(&nonce);
    replay_token[V2_NONCE_SIZE..].copy_from_slice(&tag);
    let ciphertext = &container[V2_NONCE_SIZE + V2_TAG_SIZE..];
    let mut inner = xor_stream(key.as_bytes(), &nonce, &tag, context, ciphertext);
    let expected_tag = authentication_tag(key.as_bytes(), &nonce, context, &inner);
    if !fixed_tag_eq(&tag, &expected_tag) {
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
    Ok((DecryptedBytes(plaintext), replay_token))
}

pub fn decrypt_bytes(
    encoded: &str,
    key: &VaultKey,
    context: &[u8],
) -> Result<DecryptedBytes, VaultError> {
    decrypt_bytes_with_token(encoded, key, context).map(|(plaintext, _)| plaintext)
}

pub fn decrypt_bytes_once(
    encoded: &str,
    key: &VaultKey,
    context: &[u8],
    replay_guard: &mut ReplayGuard,
) -> Result<DecryptedBytes, VaultError> {
    let (plaintext, replay_token) = decrypt_bytes_with_token(encoded, key, context)?;
    replay_guard.record(replay_token)?;
    Ok(plaintext)
}

pub fn decrypt_text(
    encoded: &str,
    key: &VaultKey,
    context: &[u8],
) -> Result<DecryptedText, VaultError> {
    let decrypted = decrypt_bytes(encoded, key, context)?;
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

pub fn decrypt_text_once(
    encoded: &str,
    key: &VaultKey,
    context: &[u8],
    replay_guard: &mut ReplayGuard,
) -> Result<DecryptedText, VaultError> {
    let decrypted = decrypt_bytes_once(encoded, key, context, replay_guard)?;
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

#[cfg(test)]
mod tests {
    use super::{
        V2_MAX_CONTEXT_SIZE, V2_MAX_INNER_SIZE, VaultKey, decrypt_bytes, encrypt_with_random,
        padded_inner_length,
    };
    use crate::{MAX_PLAINTEXT_SIZE, VaultError, random::RandomSource, v2_encoding};

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
    fn forced_nonce_reuse_does_not_reuse_plaintext_stream() {
        let key = VaultKey::from_bytes([3; 64]);
        let first = encrypt_with_random(
            b"known plaintext AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &key,
            b"context",
            &mut FixedRandom(7),
        )
        .unwrap();
        let second = encrypt_with_random(
            b"other plaintext BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            &key,
            b"context",
            &mut FixedRandom(7),
        )
        .unwrap();
        let first_binary = v2_encoding::decode(&first, usize::MAX).unwrap();
        let second_binary = v2_encoding::decode(&second, usize::MAX).unwrap();
        assert_eq!(&first_binary[..24], &second_binary[..24]);
        assert_ne!(&first_binary[24..56], &second_binary[24..56]);
        assert_ne!(&first_binary[56..88], &second_binary[56..88]);
        assert_eq!(
            decrypt_bytes(&first, &key, b"context").unwrap().as_slice(),
            b"known plaintext AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
    }

    #[test]
    fn fixed_full_container_vector() {
        let key = VaultKey::from_bytes([3; 64]);
        let encoded =
            encrypt_with_random("Привет".as_bytes(), &key, b"context", &mut FixedRandom(7))
                .unwrap();
        assert_eq!(
            encoded,
            "_Ak7i~yNPg9AEUKTBJVGFwgZSpsMnU5fHKKUxux-Bb3-rl4lK_caXfJxH23j-NFa74HzQxogVu~sPoc-FQrq~BCuNavYRTulCkrX8eV4VXc5mkpKI9wMVw"
        );
    }

    #[test]
    fn size_boundaries_are_checked_without_overflow() {
        assert_eq!(
            padded_inner_length(MAX_PLAINTEXT_SIZE),
            Ok(V2_MAX_INNER_SIZE)
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
                &vec![0; V2_MAX_CONTEXT_SIZE + 1],
                &mut FixedRandom(1)
            ),
            Err(VaultError::InputTooLarge)
        ));
    }
}
