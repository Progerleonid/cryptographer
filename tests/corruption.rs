use obsidian_vault::{VaultError, VaultKey, decrypt_text, encrypt_text};

const CONTEXT: &[u8] = b"authenticated-context";

fn fixture() -> (String, VaultKey) {
    let key = VaultKey::from_bytes([7; 64]);
    let encrypted =
        encrypt_text("Проверка целостности 🔎", &key, CONTEXT).expect("fixture encryption failed");
    (encrypted, key)
}

fn replace_character(value: &str, index: usize) -> String {
    let mut changed = value.as_bytes().to_vec();
    changed[index] = if changed[index] == b'A' { b'B' } else { b'A' };
    String::from_utf8(changed).expect("ASCII fixture")
}

#[test]
fn every_container_region_is_authenticated() {
    let (encoded, key) = fixture();
    for binary_offset in [0, 7, 8, 23, 24, 47, 48, 79, 80, 111] {
        let text_offset = 4 + binary_offset * 4 / 3;
        let changed = replace_character(&encoded, text_offset.min(encoded.len() - 1));
        assert!(matches!(
            decrypt_text(&changed, &key, CONTEXT),
            Err(VaultError::InvalidData)
        ));
    }
}

#[test]
fn wrong_key_and_context_are_rejected() {
    let (encoded, key) = fixture();
    assert!(matches!(
        decrypt_text(&encoded, &VaultKey::from_bytes([8; 64]), CONTEXT),
        Err(VaultError::InvalidData)
    ));
    assert!(matches!(
        decrypt_text(&encoded, &key, b"other-context"),
        Err(VaultError::InvalidData)
    ));
}

#[test]
fn malformed_and_noncanonical_text_is_rejected() {
    let key = VaultKey::from_bytes([1; 64]);
    for value in ["", "OV1-AAAA", "A", "AAAA0AAA", "!not-valid!", "AAA"] {
        assert!(matches!(
            decrypt_text(value, &key, CONTEXT),
            Err(VaultError::InvalidData)
        ));
    }
}
