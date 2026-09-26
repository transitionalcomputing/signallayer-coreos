// Crockford base32, most significant bit first. Encoding writes zero padding
// bits; decoding accepts only the exact symbol count with zero padding bits.
// Because the symbol-to-bit mapping is a bijection on that set, every accepted
// string is the encoding of exactly one byte string and vice versa.

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub const PAIRING_CODE_BYTES: usize = 5;
pub const PAIRING_CODE_SYMBOLS: usize = 8;
pub const RECOVERY_KEY_BYTES: usize = 16;
pub const RECOVERY_KEY_SYMBOLS: usize = 26;

fn symbol_value(symbol: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|&candidate| candidate == symbol)
        .map(|value| value as u8)
}

fn encode<const N: usize>(bytes: &[u8; N], symbols: usize) -> String {
    debug_assert!(symbols * 5 >= N * 8 && symbols * 5 - N * 8 < 5);
    let mut out = String::with_capacity(symbols);
    let mut buffer: u16 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[usize::from((buffer >> bits) & 31)] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[usize::from((buffer << (5 - bits)) & 31)] as char);
    }
    out
}

// `symbols` must already be exact, uppercase alphabet members.
fn decode<const N: usize>(symbols: &[u8]) -> Option<[u8; N]> {
    if symbols.len() * 5 < N * 8 || symbols.len() * 5 - N * 8 >= 5 {
        return None;
    }
    let padding = symbols.len() * 5 - N * 8;
    let mut out = [0u8; N];
    let mut buffer: u16 = 0;
    let mut bits = 0;
    let mut index = 0;
    for (position, &symbol) in symbols.iter().enumerate() {
        let value = symbol_value(symbol)?;
        if position == symbols.len() - 1 && value & ((1 << padding) - 1) != 0 {
            return None;
        }
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[index] = (buffer >> bits) as u8;
            index += 1;
        }
    }
    (index == N).then_some(out)
}

pub fn encode_pairing_code(code: &[u8; PAIRING_CODE_BYTES]) -> String {
    encode(code, PAIRING_CODE_SYMBOLS)
}

/// Accepts the 8 symbols case-insensitively, optionally as `XXXX-XXXX`.
pub fn parse_pairing_code(input: &str) -> Option<[u8; PAIRING_CODE_BYTES]> {
    let bytes = input.as_bytes();
    let symbols: Vec<u8> = match bytes.len() {
        8 => bytes.to_vec(),
        9 if bytes[4] == b'-' => [&bytes[..4], &bytes[5..]].concat(),
        _ => return None,
    };
    let upper: Vec<u8> = symbols.iter().map(u8::to_ascii_uppercase).collect();
    decode(&upper)
}

pub fn encode_recovery_key(key: &[u8; RECOVERY_KEY_BYTES]) -> String {
    encode(key, RECOVERY_KEY_SYMBOLS)
}

/// Accepts only the canonical form: exactly 26 uppercase symbols with the
/// final symbol's 2 padding bits zero.
pub fn parse_recovery_key(input: &str) -> Option<[u8; RECOVERY_KEY_BYTES]> {
    if input.len() != RECOVERY_KEY_SYMBOLS {
        return None;
    }
    decode(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent reference: the key as one integer, shifted left by the two
    // padding bits, split into 26 five-bit symbols.
    fn reference_key_encoding(key: &[u8; 16]) -> String {
        let value = u128::from_be_bytes(*key);
        let mut out = String::new();
        for index in 0..25 {
            let symbol = (value >> (123 - 5 * index)) & 31;
            out.push(ALPHABET[symbol as usize] as char);
        }
        out.push(ALPHABET[((value & 7) << 2) as usize] as char);
        out
    }

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn hex16(hex: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap();
        }
        out
    }

    const KEY_VECTORS: [(&str, &str); 6] = [
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "ZZZZZZZZZZZZZZZZZZZZZZZZZW",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "000G40R40M30E209185GR38E1W",
        ),
        (
            "80000000000000000000000000000000",
            "G0000000000000000000000000",
        ),
        (
            "00000000000000000000000000000001",
            "00000000000000000000000004",
        ),
        (
            "0123456789abcdeffedcba9876543210",
            "04HMASW9NF6YZZPWQAC7CN1J20",
        ),
    ];

    #[test]
    fn recovery_key_known_vectors_encode_and_decode() {
        for (hex, encoded) in KEY_VECTORS {
            let key = hex16(hex);
            assert_eq!(encode_recovery_key(&key), encoded);
            assert_eq!(reference_key_encoding(&key), encoded);
            assert_eq!(parse_recovery_key(encoded), Some(key));
        }
    }

    #[test]
    fn recovery_key_final_symbol_holds_three_bits_and_zero_padding() {
        for low in 0u8..8 {
            let mut key = [0u8; 16];
            key[15] = low;
            let encoded = encode_recovery_key(&key);
            let last = symbol_value(*encoded.as_bytes().last().unwrap()).unwrap();
            assert_eq!(last, low << 2);
            assert_eq!(parse_recovery_key(&encoded), Some(key));
        }
    }

    #[test]
    fn recovery_key_rejects_every_nonzero_padding_variant() {
        for (_, encoded) in KEY_VECTORS {
            let prefix = &encoded[..25];
            let last = symbol_value(encoded.as_bytes()[25]).unwrap();
            assert_eq!(last & 3, 0);
            for padding in 1u8..4 {
                let variant = format!("{prefix}{}", ALPHABET[usize::from(last | padding)] as char);
                assert_eq!(parse_recovery_key(&variant), None, "{variant}");
            }
        }
    }

    #[test]
    fn recovery_key_deterministic_sample_round_trips_against_reference() {
        let mut state = 0x5C_A0_0003;
        for _ in 0..20_000 {
            let mut key = [0u8; 16];
            key[..8].copy_from_slice(&splitmix(&mut state).to_be_bytes());
            key[8..].copy_from_slice(&splitmix(&mut state).to_be_bytes());
            let encoded = encode_recovery_key(&key);
            assert_eq!(encoded, reference_key_encoding(&key));
            assert_eq!(parse_recovery_key(&encoded), Some(key));
            assert_eq!(
                parse_recovery_key(&encoded.to_ascii_lowercase()).is_some(),
                encoded.bytes().all(|symbol| symbol.is_ascii_digit())
            );
        }
    }

    #[test]
    fn recovery_key_rejects_non_canonical_forms() {
        let canonical = "04HMASW9NF6YZZPWQAC7CN1J20";
        for input in [
            "",
            "04HMASW9NF6YZZPWQAC7CN1J2",
            "04HMASW9NF6YZZPWQAC7CN1J200",
            "04hmasw9nf6yzzpwqac7cn1j20",
            "04HMASW9NF6YZZPWQAC7CN1J2O",
            "04HMASW9NF6YZZPWQAC7CN1J2U",
            "04HMASW9NF6YZZPWQAC7CN1J2-",
            "04HMASW9N-F6YZZPWQAC7CN1J20",
            " 04HMASW9NF6YZZPWQAC7CN1J20",
            "I4HMASW9NF6YZZPWQAC7CN1J20",
            "L4HMASW9NF6YZZPWQAC7CN1J20",
            "04HMASW9NF6YZZPWQAC7CN1J2\u{e9}",
        ] {
            assert_eq!(parse_recovery_key(input), None, "{input}");
        }
        assert!(parse_recovery_key(canonical).is_some());
    }

    #[test]
    fn pairing_code_vectors_and_accepted_forms() {
        for (bytes, encoded) in [
            ([0u8; 5], "00000000"),
            ([0xff; 5], "ZZZZZZZZ"),
            ([0x01, 0x23, 0x45, 0x67, 0x89], "04HMASW9"),
            ([0xde, 0xad, 0xbe, 0xef, 0x01], "VTPVXVR1"),
        ] {
            assert_eq!(encode_pairing_code(&bytes), encoded);
            let lower = encoded.to_ascii_lowercase();
            let hyphenated = format!("{}-{}", &encoded[..4], &encoded[4..]);
            let lower_hyphenated = format!("{}-{}", &lower[..4], &lower[4..]);
            for input in [encoded, &lower, &hyphenated, &lower_hyphenated] {
                assert_eq!(parse_pairing_code(input), Some(bytes), "{input}");
            }
        }
    }

    #[test]
    fn pairing_code_rejects_malformed_input() {
        for input in [
            "",
            "04HMASW",
            "04HMASW9A",
            "04HM-ASW9-",
            "04H-MASW9",
            "04HMASW-9",
            "04HMASWU",
            "04HMASWI",
            "04HM ASW9",
            "04HM--SW9",
            "04HMASW\u{e9}",
        ] {
            assert_eq!(parse_pairing_code(input), None, "{input}");
        }
    }

    #[test]
    fn pairing_code_deterministic_sample_round_trips() {
        let mut state = 40;
        for _ in 0..20_000 {
            let bytes: [u8; 5] = splitmix(&mut state).to_be_bytes()[..5].try_into().unwrap();
            let encoded = encode_pairing_code(&bytes);
            assert_eq!(encoded.len(), 8);
            assert_eq!(parse_pairing_code(&encoded), Some(bytes));
        }
    }
}
