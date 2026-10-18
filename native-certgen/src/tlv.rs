//! Minimal DER TLV reader shared by the hand-rolled parsers.
//!
//! The leaf hack walks attestation extensions and the keybox parser walks SEC1/PKCS#8 keys and
//! certificate chains. Both need to split a buffer into elements while copying untouched fields
//! byte for byte, which a full ASN.1 stack would not preserve, so the reader lives here.

use crate::error::{CertGenError, Result};

/// Universal-class tag numbers compared against after the class and constructed bits are stripped.
pub const TAG_INTEGER: u32 = 0x02;
pub const TAG_BIT_STRING: u32 = 0x03;
pub const TAG_OCTET_STRING: u32 = 0x04;
pub const TAG_OID: u32 = 0x06;
pub const TAG_SEQUENCE: u32 = 0x10;

/// Reads one DER TLV, returning `(tag_number, content, total_length)`. The tag number is the raw
/// low-tag/high-tag value with the class and constructed bits stripped, which is all the parsers
/// here need.
pub fn read_tlv(data: &[u8]) -> Result<(u32, &[u8], usize)> {
    let first = *data
        .first()
        .ok_or_else(|| CertGenError::SerializationFailed("truncated DER tag".into()))?;

    let (tag_number, tag_len) = if first & 0x1F != 0x1F {
        ((first & 0x1F) as u32, 1)
    } else {
        let mut number: u32 = 0;
        let mut i = 1;
        loop {
            let byte = *data
                .get(i)
                .ok_or_else(|| CertGenError::SerializationFailed("truncated high-tag DER".into()))?;
            number = (number << 7) | (byte & 0x7F) as u32;
            if byte & 0x80 == 0 {
                break;
            }
            i += 1;
        }
        (number, i + 1)
    };

    let length_first = *data
        .get(tag_len)
        .ok_or_else(|| CertGenError::SerializationFailed("truncated DER length".into()))?;
    let (content_len, len_bytes) = if length_first < 0x80 {
        (length_first as usize, 1)
    } else {
        let count = (length_first & 0x7F) as usize;
        if count == 0 || count > 4 {
            return Err(CertGenError::SerializationFailed("unsupported DER length form".into()));
        }
        let mut length = 0usize;
        for i in 0..count {
            let byte = *data
                .get(tag_len + 1 + i)
                .ok_or_else(|| CertGenError::SerializationFailed("truncated multi-byte DER length".into()))?;
            length = (length << 8) | byte as usize;
        }
        (length, 1 + count)
    };

    let header_len = tag_len + len_bytes;
    let total_len = header_len + content_len;
    if total_len > data.len() {
        return Err(CertGenError::SerializationFailed("DER value extends beyond buffer".into()));
    }
    Ok((tag_number, &data[header_len..total_len], total_len))
}

/// Splits a buffer of concatenated DER TLVs into the raw bytes of each element.
pub fn iter_tlvs(data: &[u8]) -> Result<Vec<&[u8]>> {
    let mut elements = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (_, _, total) = read_tlv(&data[offset..])?;
        elements.push(&data[offset..offset + total]);
        offset += total;
    }
    Ok(elements)
}
