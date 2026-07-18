use obsidian_vault::{VaultKey, decrypt_bytes, encrypt_bytes};

#[test]
fn v3_transport_is_versioned_url_safe_and_has_no_zero() {
    let key = VaultKey::from_bytes([3; 64]);
    for length in 0..128 {
        let encoded = encrypt_bytes(&vec![length as u8; length], &key, b"encoding")
            .expect("encryption failed");
        assert!(encoded.is_ascii());
        assert!(encoded.starts_with("OV3-"));
        assert!(!encoded.contains('0'));
        assert!(!encoded.contains('='));
        assert!(
            encoded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~'))
        );
        assert_eq!(
            decrypt_bytes(&encoded, &key, b"encoding")
                .expect("decryption failed")
                .as_slice(),
            vec![length as u8; length]
        );
    }
}
