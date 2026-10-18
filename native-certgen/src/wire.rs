//! Bounds-checked reader shared by the native request blobs.
//!
//! Every JNI entry point receives one length-prefixed byte array (see [`crate::chaingen`] and
//! [`crate::attreq`]) and decodes it field by field. Keeping a single forward cursor here means a
//! malformed request can never be partially interpreted: each field is length-checked before it is
//! read, and each decoder rejects trailing bytes once the last field is consumed.

use crate::error::{CertGenError, Result};

/// A forward-only reader over a request blob that bounds-checks every field access.
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| malformed("field length overflow"))?;
        if end > self.data.len() {
            return Err(malformed("unexpected end of request"));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    /// Reads a big-endian `u32`; used for both lengths and raw `i32` values reinterpreted at the
    /// call site.
    pub fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    /// Reads a presence byte followed by an `i32` when set, modelling an optional enum-valued
    /// field that the Kotlin caller may leave unset.
    pub fn optional_i32(&mut self) -> Result<Option<i32>> {
        Ok(if self.bool()? { Some(self.i32()?) } else { None })
    }

    pub fn i64(&mut self) -> Result<i64> {
        let bytes = self.take(8)?;
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        Ok(i64::from_be_bytes(value))
    }

    pub fn length_prefixed(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
    /// Bytes left after the cursor. Used to reject an impossible element count before any
    /// allocation happens.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    /// Rejects a count that cannot possibly be backed by the remaining bytes.
    ///
    /// The count comes straight off the wire, so it must never reach `Vec::with_capacity`
    /// unchecked: a hostile blob could otherwise ask for a 4 Gi-element vector, and a failed
    /// allocation aborts the process (`panic = "abort"`), taking the daemon down with it.
    fn bounded_count(&self, count: u32, width: usize) -> Result<usize> {
        let count = count as usize;
        let limit = self.remaining() / width;
        if count > limit {
            return Err(malformed("element count exceeds the remaining request"));
        }
        Ok(count)
    }

    /// Reads a length-prefixed field, mapping the empty case to `None` so the caller can model an
    /// absent optional value on the wire.
    pub fn optional_length_prefixed(&mut self) -> Result<Option<Vec<u8>>> {
        let bytes = self.length_prefixed()?;
        Ok(if bytes.is_empty() { None } else { Some(bytes) })
    }

    pub fn i32_vec(&mut self) -> Result<Vec<i32>> {
        let raw_count = self.u32()?;
        let count = self.bounded_count(raw_count, 4)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.i32()?);
        }
        Ok(values)
    }

    pub fn i64_vec(&mut self) -> Result<Vec<i64>> {
        let raw_count = self.u32()?;
        let count = self.bounded_count(raw_count, 8)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.i64()?);
        }
        Ok(values)
    }

    pub fn is_at_end(&self) -> bool {
        self.pos >= self.data.len()
    }
}

/// The shared error for a truncated or over-long request blob.
pub fn malformed(msg: &str) -> CertGenError {
    CertGenError::InvalidParameter(format!("malformed request: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i32_vec_rejects_an_impossible_count() {
        // The count field claims 4 Gi entries while only four payload bytes follow.
        let blob = [0xffu8, 0xff, 0xff, 0xff, 0, 0, 0, 1];
        let mut cursor = Cursor::new(&blob);
        assert!(cursor.i32_vec().is_err());
    }

    #[test]
    fn i32_vec_accepts_a_supported_count() {
        let blob = [0u8, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 6];
        let mut cursor = Cursor::new(&blob);
        assert_eq!(cursor.i32_vec().ok(), Some(vec![5, 6]));
        assert!(cursor.is_at_end());
    }

    #[test]
    fn i64_vec_rejects_an_impossible_count() {
        let blob = [0u8, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut cursor = Cursor::new(&blob);
        assert!(cursor.i64_vec().is_err());
    }

    #[test]
    fn length_prefixed_rejects_a_truncated_field() {
        let blob = [0u8, 0, 0, 8, 1, 2];
        let mut cursor = Cursor::new(&blob);
        assert!(cursor.length_prefixed().is_err());
    }
}
