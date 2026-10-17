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

    /// Reads a length-prefixed field, mapping the empty case to `None` so the caller can model an
    /// absent optional value on the wire.
    pub fn optional_length_prefixed(&mut self) -> Result<Option<Vec<u8>>> {
        let bytes = self.length_prefixed()?;
        Ok(if bytes.is_empty() { None } else { Some(bytes) })
    }

    pub fn i32_vec(&mut self) -> Result<Vec<i32>> {
        let count = self.u32()? as usize;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.i32()?);
        }
        Ok(values)
    }

    pub fn i64_vec(&mut self) -> Result<Vec<i64>> {
        let count = self.u32()? as usize;
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
