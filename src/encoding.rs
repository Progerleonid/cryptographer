use crate::{MAX_CONTAINER_SIZE, MAX_TEXT_SIZE, error::VaultError};

#[cfg(test)]
const ALPHABET: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";
pub const TEXT_PREFIX: &str = "OV1-";

fn alphabet_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'Z' => Some(byte - b'A' + 10),
        b'a'..=b'z' => Some(byte - b'a' + 36),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
fn encode_six_bit(data: &[u8]) -> String {
    let output_len = data.len().saturating_mul(4).div_ceil(3);
    let mut output = String::with_capacity(output_len);
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        output.push(char::from(ALPHABET[usize::from(chunk[0] >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((chunk[0] & 3) << 4) | (chunk[1] >> 4))],
        ));
        output.push(char::from(
            ALPHABET[usize::from(((chunk[1] & 15) << 2) | (chunk[2] >> 6))],
        ));
        output.push(char::from(ALPHABET[usize::from(chunk[2] & 63)]));
    }

    let remainder = chunks.remainder();
    if remainder.len() == 1 {
        output.push(char::from(ALPHABET[usize::from(remainder[0] >> 2)]));
        output.push(char::from(ALPHABET[usize::from((remainder[0] & 3) << 4)]));
    } else if remainder.len() == 2 {
        output.push(char::from(ALPHABET[usize::from(remainder[0] >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((remainder[0] & 3) << 4) | (remainder[1] >> 4))],
        ));
        output.push(char::from(ALPHABET[usize::from((remainder[1] & 15) << 2)]));
    }
    output
}

fn decode_six_bit(input: &str, max_output: usize) -> Result<Vec<u8>, VaultError> {
    if !input.is_ascii() || input.len() % 4 == 1 {
        return Err(VaultError::InvalidData);
    }
    let estimated = input.len().checked_mul(3).ok_or(VaultError::InvalidData)? / 4;
    if estimated > max_output {
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

pub fn decode_key(encoded: &str) -> Result<[u8; 96], VaultError> {
    if encoded.len() != 128 {
        return Err(VaultError::InvalidData);
    }
    let decoded = decode_six_bit(encoded, 96)?;
    decoded.try_into().map_err(|_| VaultError::InvalidData)
}

pub fn decode_container(encoded: &str) -> Result<Vec<u8>, VaultError> {
    if encoded.len() > MAX_TEXT_SIZE || !encoded.starts_with(TEXT_PREFIX) {
        return Err(VaultError::InvalidData);
    }
    decode_six_bit(&encoded[TEXT_PREFIX.len()..], MAX_CONTAINER_SIZE)
}

#[cfg(test)]
mod tests {
    use super::{decode_six_bit, encode_six_bit};

    #[test]
    fn all_remainders_round_trip() {
        for length in 0..20 {
            let input: Vec<u8> = (0..length).map(|n| n as u8).collect();
            let encoded = encode_six_bit(&input);
            assert_eq!(decode_six_bit(&encoded, 100), Ok(input));
        }
    }
}
