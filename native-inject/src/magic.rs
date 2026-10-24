//! Random marker strings, used to find the injected code in the target's memory.
//!
//! This replaces `generateMagic()`. The C++ version instantiated `std::mt19937` from
//! `std::random_device` on every call and drew from a `uniform_int_distribution`; the version below
//! reads `/dev/urandom` and rejects the top of the byte range instead, which removes the seeding
//! question entirely and keeps the distribution uniform without a modulo bias.

use std::fs::File;
use std::io::Read;

/// The alphabet a marker is drawn from; identical to `kRandomChars` in `inject/utils.cpp`.
pub const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Number of random bytes consumed per call when more characters are needed.
const CHUNK: usize = 256;

/// Draws `length` characters from [`ALPHABET`], or `None` if the entropy source cannot be read.
pub fn generate(length: usize) -> Option<Vec<u8>> {
    if length == 0 {
        return Some(Vec::new());
    }
    // 248 is 62 * 4, so every index below it maps onto the alphabet with equal probability once
    // taken modulo the alphabet length; bytes at or above it are rejected and redrawn.
    let limit = (ALPHABET.len() * 4) as u8;
    let mut source = File::open("/dev/urandom").ok()?;
    let mut bytes = [0u8; CHUNK];
    let mut out = Vec::with_capacity(length);
    while out.len() < length {
        let wanted = (length - out.len()).min(CHUNK);
        let read = source.read(&mut bytes[..wanted]).ok()?;
        if read == 0 {
            return None;
        }
        for byte in &bytes[..read] {
            if out.len() == length {
                break;
            }
            if *byte < limit {
                out.push(ALPHABET[(*byte % ALPHABET.len() as u8) as usize]);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_only_characters_from_the_alphabet() {
        let magic = generate(crate::MAIN_MAGIC_LENGTH).unwrap();
        assert_eq!(magic.len(), crate::MAIN_MAGIC_LENGTH);
        assert!(magic.iter().all(|byte| ALPHABET.contains(byte)));
    }

    #[test]
    fn a_zero_length_request_yields_nothing() {
        assert_eq!(generate(0).as_deref(), Some(&[][..]));
    }

    #[test]
    fn two_draws_differ() {
        let first = generate(32).unwrap();
        let second = generate(32).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn handles_lengths_past_one_chunk() {
        let magic = generate(1000).unwrap();
        assert_eq!(magic.len(), 1000);
        assert!(magic.iter().all(|byte| ALPHABET.contains(byte)));
    }
}
