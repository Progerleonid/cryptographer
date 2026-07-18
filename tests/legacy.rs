use obsidian_vault::{VaultKey, decrypt_ov1_text, decrypt_text};

const LEGACY_KEY: &str = "1mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS71mS7";
const LEGACY_CONTAINER: &str = "OV1-Jq9JLanKC341eG00000000iB2miB2miB2miB2miB2miB2miB2miB2miB2miB2miB3GqD3GqD3GqD3GqD3GqD3GqD3GqD3GqD3GqD3GqD3Gq00W00000009Cu99QZebXnFPojApe351OnI9LMEiIx7XTp1XOQPFCQ3M_SO4iCzlwgEzMNKt4t5gH1xCo30kJ5o6owAYeFnYPKJIti_cluRt4yv73XSiDj8yFnRvQrKkUPV3RGCV9mEzLbNbtFAHskj1ThUKIl9P6TqTlw6rEEeWI4GVJNFvInsLOj9L9srkG0W0Y2fDZqpNQDy5MmNtp2nZQk_FSzau0_RpYQKL9j4QEkk1I_FivZLSVM2L5cwSwzmo2k2tKseKb7FlPHcojBOWShkYeqFWi5aAzjMo4fJSTrpd7nL20u-2PGdxDykJmeT2iTlgNbnYxFtvpqDLBKifYi3FpOOAnWdpg-ioydirFv-VAs7Bgiz6wLTnY0AnBCd8NxHUB0NxzUFQ7HWiqiNYVpYadO6ZZBnuuAPqKqe-3YE_J8KljdYMTgMCbjbubGFax9RX5X3iilX1J7FSYT8UaKMpGLsq5EcEdnRXwpt81iFYMh4Nv2oJGNvmjacdv5G2Txx4tTTI63aucyfHXzJtDLp09vunqZKleueKCpdPHGzVfuW4JN55r5hygM-en4nRo3nBJtfYolo68GY0DsmTBmQd8Lb0ElzeMnSNyY44iAdpdajGTmYo_Q0azBSoZZaTbK3qVP8OhdxAtTn4tmX_NxUTMl5ma7UWIat3D3oa9IIMzrEUM9mvYVd1NQa_1uhdQNYnNgg_rUcmsauW92yAEVF8GGIMW";

#[test]
fn saved_ov1_vector_remains_readable() {
    let plaintext =
        decrypt_ov1_text(LEGACY_CONTAINER, LEGACY_KEY).expect("legacy vector must remain readable");
    assert_eq!(plaintext.as_str(), "legacy migration");
}

#[test]
fn saved_v2_vector_remains_readable_through_current_api() {
    const V2_CONTAINER: &str = "_Ak7i~yNPg9AEUKTBJVGFwgZSpsMnU5fHKKUxux-Bb3-rl4lK_caXfJxH23j-NFa74HzQxogVu~sPoc-FQrq~BCuNavYRTulCkrX8eV4VXc5mkpKI9wMVw";
    let key = VaultKey::from_bytes([3; 64]);
    let plaintext =
        decrypt_text(V2_CONTAINER, &key, b"context").expect("saved V2 vector must remain readable");
    assert_eq!(plaintext.as_str(), "Привет");
}
