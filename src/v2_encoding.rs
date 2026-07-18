use crate::error::VaultError;

pub const V2_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789-_~";

const fn build_decode_table() -> [u8; 256] {
    let mut table = [u8::MAX; 256];
    let mut value = 0;
    while value < V2_ALPHABET.len() {
        table[V2_ALPHABET[value] as usize] = value as u8;
        value += 1;
    }
    table
}

const DECODE_TABLE: [u8; 256] = build_decode_table();

fn alphabet_value(byte: u8) -> Option<u8> {
    let value = DECODE_TABLE[usize::from(byte)];
    (value != u8::MAX).then_some(value)
}

pub fn encode(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len().saturating_mul(4).div_ceil(3));
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        output.push(char::from(V2_ALPHABET[usize::from(chunk[0] >> 2)]));
        output.push(char::from(
            V2_ALPHABET[usize::from(((chunk[0] & 3) << 4) | (chunk[1] >> 4))],
        ));
        output.push(char::from(
            V2_ALPHABET[usize::from(((chunk[1] & 15) << 2) | (chunk[2] >> 6))],
        ));
        output.push(char::from(V2_ALPHABET[usize::from(chunk[2] & 63)]));
    }
    match chunks.remainder() {
        [a] => {
            output.push(char::from(V2_ALPHABET[usize::from(a >> 2)]));
            output.push(char::from(V2_ALPHABET[usize::from((a & 3) << 4)]));
        }
        [a, b] => {
            output.push(char::from(V2_ALPHABET[usize::from(a >> 2)]));
            output.push(char::from(
                V2_ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))],
            ));
            output.push(char::from(V2_ALPHABET[usize::from((b & 15) << 2)]));
        }
        _ => {}
    }
    output
}

pub fn decode(input: &str, maximum: usize) -> Result<Vec<u8>, VaultError> {
    if !input.is_ascii() || input.starts_with("OV1-") || input.len() % 4 == 1 {
        return Err(VaultError::InvalidData);
    }
    let estimated = input.len().checked_mul(3).ok_or(VaultError::InvalidData)? / 4;
    if estimated > maximum {
        return Err(VaultError::InvalidData);
    }

    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(estimated);
    let mut index = 0;
    while index + 4 <= bytes.len() {
        let a = alphabet_value(bytes[index]).ok_or(VaultError::InvalidData)?;
        let b = alphabet_value(bytes[index + 1]).ok_or(VaultError::InvalidData)?;
        let c = alphabet_value(bytes[index + 2]).ok_or(VaultError::InvalidData)?;
        let d = alphabet_value(bytes[index + 3]).ok_or(VaultError::InvalidData)?;
        output.push((a << 2) | (b >> 4));
        output.push((b << 4) | (c >> 2));
        output.push((c << 6) | d);
        index += 4;
    }
    match bytes.len() - index {
        0 => {}
        2 => {
            let a = alphabet_value(bytes[index]).ok_or(VaultError::InvalidData)?;
            let b = alphabet_value(bytes[index + 1]).ok_or(VaultError::InvalidData)?;
            if b & 0x0f != 0 {
                return Err(VaultError::InvalidData);
            }
            output.push((a << 2) | (b >> 4));
        }
        3 => {
            let a = alphabet_value(bytes[index]).ok_or(VaultError::InvalidData)?;
            let b = alphabet_value(bytes[index + 1]).ok_or(VaultError::InvalidData)?;
            let c = alphabet_value(bytes[index + 2]).ok_or(VaultError::InvalidData)?;
            if c & 0x03 != 0 {
                return Err(VaultError::InvalidData);
            }
            output.push((a << 2) | (b >> 4));
            output.push((b << 4) | (c >> 2));
        }
        _ => return Err(VaultError::InvalidData),
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{DECODE_TABLE, V2_ALPHABET, decode, encode};

    #[test]
    fn decoding_uses_a_direct_byte_table() {
        for (value, byte) in V2_ALPHABET.iter().copied().enumerate() {
            assert_eq!(DECODE_TABLE[usize::from(byte)], value as u8);
        }
        assert_eq!(DECODE_TABLE[0], u8::MAX);
        assert_eq!(DECODE_TABLE[usize::from(b'0')], u8::MAX);
    }

    #[test]
    fn all_remainders_round_trip_canonically() {
        for length in 0..100 {
            let input: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let encoded = encode(&input);
            assert!(!encoded.contains('0'));
            assert_eq!(decode(&encoded, 100), Ok(input));
        }
    }

    #[test]
    fn trailing_bits_must_be_canonical() {
        assert!(decode("AB", 10).is_err());
        assert!(decode("AAB", 10).is_err());
        assert!(decode("A", 10).is_err());
    }
}
