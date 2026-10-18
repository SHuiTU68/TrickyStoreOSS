//! Minimal DER TLV reader shared by the hand-rolled parsers.
//!
//! The leaf hack walks attestation extensions and the keybox parser walks SEC1/PKCS#8 keys and
//! certificate chains. Both need to split a buffer into elements while copying untouched fields
//! byte for byte, which a full ASN.1 stack would not preserve, so the reader lives here.
//!
//! Every offset and length below is derived with checked arithmetic and every slice is taken with
//! `get`. The buffers that reach this reader are attacker-influenced (a keybox document, a captured
//! certificate chain, a request blob), so a malformed encoding has to come back as an error and
//! never as a panic: the crate is compiled with `panic = "abort"`, which means a panic here is not
//! a recoverable bug but the end of the app process. It also matters that the length arithmetic is
//! checked rather than merely wide enough — the 32-bit Android targets this library ships for
//! cannot represent a four-octet DER length in a `usize` at all, so `(length << 8) | byte` would
//! silently wrap there and turn a bogus length into a plausible one.
use crate::error::{CertGenError, Result};

/// Universal-class tag numbers compared against after the class and constructed bits are stripped.
pub const TAG_INTEGER: u32 = 0x02;
pub const TAG_BIT_STRING: u32 = 0x03;
pub const TAG_OCTET_STRING: u32 = 0x04;
pub const TAG_OID: u32 = 0x06;
pub const TAG_SEQUENCE: u32 = 0x10;

/// The most length octets DER allows after the leading one. Four octets already describe 4 GiB, far
/// past anything this crate hands over a JNI boundary, and bounding the count keeps the shift below
/// inside `u32`.
const MAX_LENGTH_OCTETS: usize = 4;

/// Builds the single error every malformed-input path here reports.
fn truncated(message: &'static str) -> CertGenError {
    CertGenError::SerializationFailed(message.to_string())
}

/// Reads one DER TLV, returning `(tag_number, content, total_length)`. The tag number is the raw
/// low-tag/high-tag value with the class and constructed bits stripped, which is all the parsers
/// here need.
///
/// `total_length` is the size of the whole element (header included) and is always at least two, so
/// callers that walk a buffer with it are guaranteed to make progress.
pub fn read_tlv(data: &[u8]) -> Result<(u32, &[u8], usize)> {
    let first = *data.first().ok_or_else(|| truncated("truncated DER tag"))?;
    let (tag_number, tag_len) = if first & 0x1F != 0x1F {
        ((first & 0x1F) as u32, 1)
    } else {
        let mut number: u32 = 0;
        // `index` stays inside the buffer (the `get` below fails otherwise), so the length of the
        // buffer bounds this loop.
        let mut index = 1;
        loop {
            let byte = *data.get(index).ok_or_else(|| truncated("truncated high-tag DER"))?;
            number = number
                .checked_mul(128)
                .and_then(|shifted| shifted.checked_add((byte & 0x7F) as u32))
                .ok_or_else(|| truncated("DER tag number does not fit in 32 bits"))?;
            if byte & 0x80 == 0 {
                break;
            }
            index += 1;
        }
        (number, index + 1)
    };
    let length_first = *data.get(tag_len).ok_or_else(|| truncated("truncated DER length"))?;
    let (content_len, len_bytes) = if length_first < 0x80 {
        (length_first as usize, 1)
    } else {
        let count = (length_first & 0x7F) as usize;
        if count == 0 || count > MAX_LENGTH_OCTETS {
            return Err(truncated("unsupported DER length form"));
        }
        let mut length = 0usize;
        for index in 0..count {
            let offset = tag_len
                .checked_add(1)
                .and_then(|start| start.checked_add(index))
                .ok_or_else(|| truncated("DER length offset overflows"))?;
            let byte = *data
                .get(offset)
                .ok_or_else(|| truncated("truncated multi-byte DER length"))?;
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(byte as usize))
                .ok_or_else(|| truncated("DER length does not fit in usize"))?;
        }
        (length, 1 + count)
    };
    let header_len = tag_len
        .checked_add(len_bytes)
        .ok_or_else(|| truncated("DER header overflows"))?;
    let total_len = header_len
        .checked_add(content_len)
        .ok_or_else(|| truncated("DER element overflows"))?;
    if total_len > data.len() {
        return Err(truncated("DER value extends beyond buffer"));
    }
    // `header_len <= total_len <= data.len()`, so this cannot fail, but going through `get` keeps
    // the "no indexing that can panic" rule intact if the checks above ever change.
    let content = data
        .get(header_len..total_len)
        .ok_or_else(|| truncated("DER header is inconsistent"))?;
    Ok((tag_number, content, total_len))
}

/// Splits a buffer of concatenated DER TLVs into the raw bytes of each element.
pub fn iter_tlvs(data: &[u8]) -> Result<Vec<&[u8]>> {
    let mut elements = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let rest = data
            .get(offset..)
            .ok_or_else(|| truncated("DER element offset out of range"))?;
        let (_, _, total) = read_tlv(rest)?;
        // `read_tlv` reports at least a two-byte header, so `total` is never zero and the loop
        // always advances. The addition is still checked: a length that does not fit must be an
        // error, not a wrapped offset that points back into the buffer.
        let end = offset
            .checked_add(total)
            .ok_or_else(|| truncated("DER element end overflows"))?;
        let element = data
            .get(offset..end)
            .ok_or_else(|| truncated("DER element extends beyond buffer"))?;
        elements.push(element);
        offset = end;
    }
    Ok(elements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_short_form_element() {
        let (tag, content, total) = read_tlv(&[0x04, 0x03, 0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(tag, TAG_OCTET_STRING);
        assert_eq!(content, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(total, 5);
    }

    #[test]
    fn reads_a_long_form_element() {
        let data = [0x04, 0x81, 0x02, 0x11, 0x22, 0x33];
        let (_, content, total) = read_tlv(&data).unwrap();
        assert_eq!(content, &[0x11, 0x22]);
        assert_eq!(total, 5);
    }

    #[test]
    fn rejects_an_empty_buffer() {
        assert!(read_tlv(&[]).is_err());
    }

    #[test]
    fn rejects_a_truncated_length() {
        assert!(read_tlv(&[0x30]).is_err());
        assert!(read_tlv(&[0x30, 0x82, 0x01]).is_err());
    }

    #[test]
    fn rejects_an_indefinite_length() {
        // 0x80 means "length follows in a form DER does not allow", and it must not be read as
        // "zero length octets".
        assert!(read_tlv(&[0x30, 0x80, 0x00, 0x00]).is_err());
    }

    #[test]
    fn rejects_a_length_form_wider_than_four_octets() {
        assert!(read_tlv(&[0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01]).is_err());
    }

    /// Four length octets of 0xFF describe 4 GiB: too big for a 32-bit `usize` and far bigger than
    /// any buffer that reaches this reader. It has to be an error on every target, never a wrapped
    /// "small" length.
    #[test]
    fn rejects_a_length_that_cannot_be_represented() {
        let data = [0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(read_tlv(&data).is_err());
    }

    #[test]
    fn rejects_an_element_that_runs_past_the_buffer() {
        assert!(read_tlv(&[0x04, 0x05, 0x01]).is_err());
    }

    #[test]
    fn rejects_a_high_tag_number_that_overflows() {
        // High-tag-number form whose continuation bytes never fit in the 32-bit tag field.
        let data = [0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00];
        assert!(read_tlv(&data).is_err());
    }

    #[test]
    fn reads_a_high_tag_number() {
        // [9] context-specific in high-tag form. 0x1F 0x09 is the one-octet spelling and
        // 0x1F 0x81 0x09 the two-octet one, where the 0x80 bit marks a continuation.
        let (tag, _, _) = read_tlv(&[0x1F, 0x09, 0x01, 0x7F]).unwrap();
        assert_eq!(tag, 9);
        // A continuation octet contributes seven bits, so 0x81 0x09 spells 1 * 128 + 9 = 137.
        let (tag, content, total) = read_tlv(&[0x1F, 0x81, 0x09, 0x01, 0x7F]).unwrap();
        assert_eq!(tag, 137);
        assert_eq!(content, &[0x7F]);
        assert_eq!(total, 5);
    }

    #[test]
    fn iterates_without_losing_a_zero_length_element() {
        let elements = iter_tlvs(&[0x04, 0x00, 0x04, 0x01, 0x7F]).unwrap();
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0], &[0x04, 0x00]);
        assert_eq!(elements[1], &[0x04, 0x01, 0x7F]);
    }

    #[test]
    fn iteration_rejects_a_truncated_trailing_element() {
        assert!(iter_tlvs(&[0x04, 0x01, 0x7F, 0x04, 0x02]).is_err());
    }

    #[test]
    fn iteration_of_an_empty_buffer_yields_no_elements() {
        assert!(iter_tlvs(&[]).unwrap().is_empty());
    }
}