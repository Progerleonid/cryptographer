use obsidian_vault::{VaultKey, decrypt_bytes, decrypt_text, encrypt_bytes, encrypt_text};

const CONTEXT: &[u8] = b"integration-test-context";

fn assert_roundtrip(text: &str) {
    let key = VaultKey::from_bytes([0x42; 64]);
    let encrypted = encrypt_text(text, &key, CONTEXT).expect("encryption failed");
    let decrypted = decrypt_text(&encrypted, &key, CONTEXT).expect("decryption failed");
    assert_eq!(decrypted.as_str(), text);
}

#[test]
fn text_round_trips() {
    for text in [
        "",
        "The obsidian vault opens at midnight.",
        "18446744073709551615",
        "Съешь ещё этих мягких французских булок.",
        "🔐🪨✨ Привет, мир! 🌍",
        "before\0middle\0after",
    ] {
        assert_roundtrip(text);
    }
}

#[test]
fn arbitrary_bytes_round_trip() {
    let key = VaultKey::from_bytes([7; 64]);
    let plaintext: Vec<u8> = (0_u8..=255).collect();
    let encrypted = encrypt_bytes(&plaintext, &key, CONTEXT).expect("encryption failed");
    let decrypted = decrypt_bytes(&encrypted, &key, CONTEXT).expect("decryption failed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn privet_has_compact_random_looking_shape() {
    let key = VaultKey::from_bytes([9; 64]);
    let first = encrypt_text("Привет", &key, CONTEXT).expect("encryption failed");
    let second = encrypt_text("Привет", &key, CONTEXT).expect("encryption failed");
    assert_eq!(first.len(), 154);
    assert!(first.starts_with("OV3-"));
    assert!(!first.contains('0'));
    assert_ne!(first, second);
    assert_eq!(
        decrypt_text(&first, &key, CONTEXT)
            .expect("decryption failed")
            .as_str(),
        "Привет"
    );
}

#[test]
fn padding_uses_32_byte_classes() {
    let key = VaultKey::from_bytes([11; 64]);
    for length in 0..100 {
        let encoded = encrypt_bytes(&vec![5; length], &key, CONTEXT).expect("encryption failed");
        let inner = ((8 + length) / 32 + 1) * 32;
        let binary = 8 + 16 + 24 + 32 + inner;
        assert_eq!(encoded.len(), 4 + binary.saturating_mul(4).div_ceil(3));
        assert_eq!(
            decrypt_bytes(&encoded, &key, CONTEXT)
                .expect("decryption failed")
                .as_slice(),
            vec![5; length]
        );
    }
}

#[test]
fn long_text_round_trip() {
    assert_roundtrip(&"длинная строка 🧪 ".repeat(8_192));
}
