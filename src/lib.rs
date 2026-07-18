//! Obsidian Vault V3 uses an experimental bespoke Feistel permutation, sponge,
//! MAC, XOF, and SIV construction. It has not undergone independent professional
//! cryptanalysis and must not be used to protect truly critical data.
//!
//! New encryption uses versioned V3 containers. V2 containers are detected and
//! remain decryptable; OV1 is exposed only through [`decrypt_ov1_text`].

mod container;
mod encoding;
pub mod error;
pub mod keyfile;
mod padding;
mod permutation;
mod random;
mod sponge;
mod v2;
mod v2_encoding;
mod v2_permutation;
mod v2_sponge;
mod v3;
mod v3_duplex;
pub mod v3_permutation;
mod vault;

pub use error::VaultError;
pub use v2::{
    DecryptedBytes, DecryptedText, ReplayGuard, V2_MAX_CONTAINER_SIZE, V2_MAX_CONTEXT_SIZE,
    V2_MAX_TEXT_SIZE, VaultKey, decrypt_bytes as decrypt_v2_bytes,
    decrypt_bytes_once as decrypt_v2_bytes_once, decrypt_text as decrypt_v2_text,
    decrypt_text_once as decrypt_v2_text_once,
};
pub use v3::{
    V3_MAX_CONTAINER_SIZE, V3_MAX_CONTEXT_SIZE, V3_MAX_TEXT_SIZE, V3_TEXT_PREFIX, decrypt_bytes,
    decrypt_bytes_once, decrypt_text, decrypt_text_once, encrypt_bytes, encrypt_text,
    is_v3_container,
};
pub use vault::{DecryptedText as LegacyDecryptedText, decrypt_text as decrypt_ov1_text};

pub const MAX_PLAINTEXT_SIZE: usize = 16 * 1024 * 1024;
pub(crate) const MAX_CIPHERTEXT_SIZE: usize = 16_777_728;
pub(crate) const MAX_CONTAINER_SIZE: usize = 16_777_848;
pub(crate) const MAX_TEXT_SIZE: usize = 22_370_468;
