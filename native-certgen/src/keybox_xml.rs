//! Native keybox parsing.
//!
//! The keybox is the `<AndroidAttestation>` XML document the module signs attestation chains with:
//! one or more `<Key>` entries, each holding a PEM private key and a PEM certificate chain. This
//! module mirrors the Kotlin `KeyBoxUtils.readFromXml` path — the same element names, nesting and
//! count consistency checks — and decodes the PEM material natively, handing the signing key back
//! as PKCS#8 DER.
//!
//! Traditional PEM labels (`EC PRIVATE KEY`, `RSA PRIVATE KEY`) are re-wrapped into PKCS#8 here, so
//! every later native stage always sees one key encoding. Base64 is decoded locally rather than
//! through a crate, keeping the dependency set unchanged.

use crate::attestation::{enc_integer, enc_octet_string, enc_sequence};
use crate::certbuilder::encode_der_oid;
use crate::error::{CertGenError, Result};
use crate::tlv::{iter_tlvs, read_tlv, TAG_OID, TAG_SEQUENCE};

use der::Decode;
use x509_cert::Certificate;

/// `id-ecPublicKey`, the PKCS#8 algorithm OID for an EC key.
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
/// `rsaEncryption`, the PKCS#8 algorithm OID for an RSA key.
const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];

/// The DER tag of a context-0 constructed element (`[0]`), used to spot the SEC1 curve parameters.
const CONTEXT_0_CONSTRUCTED: u8 = 0xA0;

/// One parsed keybox entry: the signing key plus the certificate chain it was issued with.
pub struct NativeKeybox {
    /// `"EC"` or `"RSA"` — the same names `KeyProperties` exposes to Kotlin.
    pub algorithm: String,
    /// The signing key as PKCS#8 DER, ready for the native signing stages.
    pub private_key_pkcs8: Vec<u8>,
    /// The certificate chain, leaf first, each certificate in DER form.
    pub certificates: Vec<Vec<u8>>,
}

/// Parses a keybox document into one entry per `<Key>`, in document order.
pub fn parse_keybox_xml(xml: &str) -> Result<Vec<NativeKeybox>> {
    let events = tokenize(xml)?;
    let mut walker = Walker { events, pos: 0 };
    walker.parse_document()
}

/// Parses a keybox document and encodes the entries as the blob the JNI entry point returns:
/// `[u32 count]{ [u32 algorithm][u32 pkcs8]{ [u32 certCount]{ [u32 cert] } } }`, all lengths
/// big-endian. Kotlin rebuilds the key pairs and certificates from it.
pub fn parse_keybox_blob(xml: &str) -> Result<Vec<u8>> {
    let keyboxes = parse_keybox_xml(xml)?;
    // Size the response once, up front: every DER body is already in hand, so the exact length is
    // known and the buffer never has to grow (which would copy the certificates a second time).
    let mut blob = Vec::with_capacity(blob_len(&keyboxes));
    blob.extend_from_slice(&(keyboxes.len() as u32).to_be_bytes());
    for keybox in &keyboxes {
        push_blob(&mut blob, keybox.algorithm.as_bytes());
        push_blob(&mut blob, &keybox.private_key_pkcs8);
        blob.extend_from_slice(&(keybox.certificates.len() as u32).to_be_bytes());
        for certificate in &keybox.certificates {
            push_blob(&mut blob, certificate);
        }
    }
    Ok(blob)
}

/// The exact byte length [`parse_keybox_blob`] is about to produce, so the response buffer can be
/// allocated once at its final size.
fn blob_len(keyboxes: &[NativeKeybox]) -> usize {
    let mut len = 4;
    for keybox in keyboxes {
        len += 4 + keybox.algorithm.len();
        len += 4 + keybox.private_key_pkcs8.len();
        len += 4;
        for certificate in &keybox.certificates {
            len += 4 + certificate.len();
        }
    }
    len
}

fn push_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// XML tokenizer
// ---------------------------------------------------------------------------

/// A token from the keybox document. A self-closing tag yields a `Start` followed by its `End`, so
/// the walker never has to special-case empty elements.
///
/// Attribute values are validated while tokenising but never stored: no element of the keybox
/// schema carries a meaningful one. Keeping them would cost one `Vec` per start tag plus a clone on
/// every `peek`, which is pure overhead on a document that is re-read on each keybox reload.
/// Dropping them also makes the event `Copy`, so `peek` returns by value without allocating.
#[derive(Clone, Copy)]
enum XmlEvent<'a> {
    Start { name: &'a str },
    End { name: &'a str },
    Text(&'a str),
}

/// Splits the document into events, skipping comments, the XML declaration and CDATA markers (CDATA
/// keeps its content, which is text as far as the walker is concerned). Whitespace-only text is
/// dropped, the same way an XML pull parser reports it as ignorable whitespace: only the text
/// between an element's tags is ever meaningful here.
fn tokenize(xml: &str) -> Result<Vec<XmlEvent<'_>>> {
    // One event per tag/text run, and tags average well over 32 bytes of source, so this estimate
    // usually avoids every reallocation. It is capped so a huge document cannot turn the guess into
    // a large speculative allocation.
    let mut events = Vec::with_capacity((xml.len() / 32).min(4096));
    let mut cursor = 0usize;
    while cursor < xml.len() {
        let rest = &xml[cursor..];
        if !rest.starts_with('<') {
            let end = rest.find('<').unwrap_or(rest.len());
            push_text(&mut events, &rest[..end]);
            cursor += end;
        } else if let Some(after_declaration) = rest.strip_prefix("<?") {
            let end = after_declaration
                .find("?>")
                .ok_or_else(|| keybox_error("unterminated XML declaration"))?;
            cursor += 2 + end + 2;
        } else if let Some(after_marker) = rest.strip_prefix("<!--") {
            let end = after_marker.find("-->").ok_or_else(|| keybox_error("unterminated XML comment"))?;
            cursor += 4 + end + 3;
        } else if let Some(after_marker) = rest.strip_prefix("<![CDATA[") {
            let end = after_marker.find("]]>").ok_or_else(|| keybox_error("unterminated CDATA section"))?;
            push_text(&mut events, &after_marker[..end]);
            cursor += 9 + end + 3;
        } else if rest.starts_with("<!") {
            let end = rest.find('>').ok_or_else(|| keybox_error("unterminated XML declaration"))?;
            cursor += end + 1;
        } else if let Some(after_marker) = rest.strip_prefix("</") {
            let end = after_marker.find('>').ok_or_else(|| keybox_error("unterminated closing tag"))?;
            events.push(XmlEvent::End { name: after_marker[..end].trim() });
            cursor += 2 + end + 1;
        } else {
            let end = find_tag_end(rest)?;
            let body = &rest[1..end];
            let (body, self_closing) = match body.strip_suffix('/') {
                Some(trimmed) => (trimmed, true),
                None => (body, false),
            };
            let name = parse_tag(body)?;
            events.push(XmlEvent::Start { name });
            if self_closing {
                events.push(XmlEvent::End { name });
            }
            cursor += end + 1;
        }
    }
    Ok(events)
}

/// Adds a text event unless it is only whitespace.
fn push_text<'a>(events: &mut Vec<XmlEvent<'a>>, text: &'a str) {
    if !text.trim().is_empty() {
        events.push(XmlEvent::Text(text));
    }
}

/// Finds the `>` closing a start tag, ignoring any that sit inside a quoted attribute value.
fn find_tag_end(tag: &str) -> Result<usize> {
    let mut quote: Option<char> = None;
    for (offset, ch) in tag.char_indices().skip(1) {
        match quote {
            Some(active) => {
                if ch == active {
                    quote = None;
                }
            }
            None => match ch {
                '"' | '\'' => quote = Some(ch),
                '>' => return Ok(offset),
                _ => {}
            },
        }
    }
    Err(keybox_error("unterminated start tag"))
}

/// Splits a start tag body into its element name and attributes. Namespace prefixes are kept, as
/// the Kotlin parser disables namespace processing too.
fn parse_tag(body: &str) -> Result<&str> {
    let name_end = body.find(char::is_whitespace).unwrap_or(body.len());
    let name = &body[..name_end];
    if name.is_empty() {
        return Err(keybox_error("empty element name"));
    }

    let mut rest = &body[name_end..];
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let equals = rest
            .find('=')
            .ok_or_else(|| keybox_error("attribute without a value"))?;
        let attr_name = rest[..equals].trim();
        if attr_name.is_empty() {
            return Err(keybox_error("empty attribute name"));
        }
        let after_equals = rest[equals + 1..].trim_start();
        let quote = after_equals
            .chars()
            .next()
            .filter(|c| *c == '"' || *c == '\'')
            .ok_or_else(|| keybox_error("unquoted attribute value"))?;
        let value_rest = &after_equals[1..];
        let end = value_rest
            .find(quote)
            .ok_or_else(|| keybox_error("unterminated attribute value"))?;
        // The value is only checked for well-formedness; nothing reads it back.
        let _ = &value_rest[..end];
        rest = &value_rest[end + 1..];
    }
    Ok(name)
}

// ---------------------------------------------------------------------------
// Document walker
// ---------------------------------------------------------------------------

struct Walker<'a> {
    events: Vec<XmlEvent<'a>>,
    pos: usize,
}

impl<'a> Walker<'a> {
    fn peek(&self) -> Result<XmlEvent<'a>> {
        self.events
            .get(self.pos)
            .copied()
            .ok_or_else(|| keybox_error("unexpected end of keybox document"))
    }

    /// Consumes a start tag, returning its name.
    fn expect_start(&mut self) -> Result<&'a str> {
        match self.peek()? {
            XmlEvent::Start { name } => {
                self.pos += 1;
                Ok(name)
            }
            _ => Err(keybox_error("expected an element")),
        }
    }

    /// Builds the entry list, enforcing the document shape: one `AndroidAttestation` root holding
    /// an optional keybox count and one or more `Keybox` blocks.
    fn parse_document(&mut self) -> Result<Vec<NativeKeybox>> {
        let name = self.expect_start()?;
        if name != "AndroidAttestation" {
            return Err(keybox_error("invalid keybox document root"));
        }

        let mut expected_keyboxes: Option<u32> = None;
        let mut keybox_blocks = 0u32;
        let mut keyboxes: Vec<NativeKeybox> = Vec::new();

        loop {
            match self.peek()? {
                XmlEvent::End { name } if name == "AndroidAttestation" => {
                    self.pos += 1;
                    break;
                }
                XmlEvent::Start { name } if name == "NumberOfKeyboxes" => {
                    if expected_keyboxes.is_some() {
                        return Err(keybox_error("duplicate keybox count"));
                    }
                    self.pos += 1;
                    expected_keyboxes = Some(parse_count(&self.leaf_text("NumberOfKeyboxes")?, "keybox")?);
                }
                XmlEvent::Start { name } if name == "Keybox" => {
                    keybox_blocks += 1;
                    self.parse_keybox(&mut keyboxes)?;
                }
                _ => return Err(keybox_error("invalid keybox document element")),
            }
        }

        if expected_keyboxes.is_some_and(|expected| expected != keybox_blocks) {
            return Err(keybox_error("incomplete keybox document"));
        }
        if keyboxes.is_empty() {
            return Err(keybox_error("keybox document has no keys"));
        }

        // The root element must be the last thing in the document.
        if self.peek().is_ok() {
            return Err(keybox_error("unexpected content after keybox document"));
        }
        Ok(keyboxes)
    }

    fn parse_keybox(&mut self, keyboxes: &mut Vec<NativeKeybox>) -> Result<()> {
        let name = self.expect_start()?;
        if name != "Keybox" {
            return Err(keybox_error("invalid keybox element"));
        }

        let mut key_count = 0usize;
        loop {
            match self.peek()? {
                XmlEvent::End { name } if name == "Keybox" => {
                    self.pos += 1;
                    break;
                }
                XmlEvent::Start { name } if name == "Key" => {
                    let keybox = self.parse_key()?;
                    // A later entry for the same algorithm replaces the earlier one, mirroring the
                    // Kotlin map put, and keeps the earlier entry's position.
                    match keyboxes.iter_mut().find(|existing| existing.algorithm == keybox.algorithm) {
                        Some(slot) => *slot = keybox,
                        None => keyboxes.push(keybox),
                    }
                    key_count += 1;
                }
                _ => return Err(keybox_error("invalid keybox element")),
            }
        }

        if key_count == 0 {
            return Err(keybox_error("incomplete keybox"));
        }
        Ok(())
    }

    /// Parses one `<Key>`: exactly one private key, and either a bare `<Certificate>` or a
    /// `<CertificateChain>` whose declared count must match the certificates it carries.
    fn parse_key(&mut self) -> Result<NativeKeybox> {
        self.expect_start()?;

        let mut private_key_text: Option<String> = None;
        let mut certificate_texts: Vec<String> = Vec::new();
        let mut chain_seen = false;

        loop {
            match self.peek()? {
                XmlEvent::End { name } if name == "Key" => {
                    self.pos += 1;
                    break;
                }
                XmlEvent::Start { name } if name == "PrivateKey" => {
                    if private_key_text.is_some() {
                        return Err(keybox_error("duplicate private key element"));
                    }
                    self.pos += 1;
                    private_key_text = Some(self.leaf_text("PrivateKey")?);
                }
                XmlEvent::Start { name } if name == "CertificateChain" => {
                    if chain_seen {
                        return Err(keybox_error("duplicate certificate chain"));
                    }
                    chain_seen = true;
                    self.parse_certificate_chain(&mut certificate_texts)?;
                }
                XmlEvent::Start { name } if name == "Certificate" => {
                    if chain_seen {
                        return Err(keybox_error("unexpected certificate element"));
                    }
                    self.pos += 1;
                    let text = self.leaf_text("Certificate")?;
                    if !text.trim().is_empty() {
                        certificate_texts.push(text);
                    }
                }
                _ => return Err(keybox_error("unexpected keybox entry")),
            }
        }

        let private_key_text =
            private_key_text.ok_or_else(|| keybox_error("keybox entry is missing key material"))?;
        if private_key_text.trim().is_empty() || certificate_texts.is_empty() {
            return Err(keybox_error("keybox entry is missing key material"));
        }
        build_entry(&private_key_text, &certificate_texts)
    }

    fn parse_certificate_chain(&mut self, certificates: &mut Vec<String>) -> Result<()> {
        let name = self.expect_start()?;
        if name != "CertificateChain" {
            return Err(keybox_error("unexpected certificate chain entry"));
        }

        let first = certificates.len();
        let mut expected: Option<u32> = None;
        loop {
            match self.peek()? {
                XmlEvent::End { name } if name == "CertificateChain" => {
                    self.pos += 1;
                    break;
                }
                XmlEvent::Start { name } if name == "NumberOfCertificates" => {
                    if expected.is_some() {
                        return Err(keybox_error("duplicate certificate count"));
                    }
                    self.pos += 1;
                    expected =
                        Some(parse_count(&self.leaf_text("NumberOfCertificates")?, "certificate")?);
                }
                XmlEvent::Start { name } if name == "Certificate" => {
                    self.pos += 1;
                    let text = self.leaf_text("Certificate")?;
                    if !text.trim().is_empty() {
                        certificates.push(text);
                    }
                }
                _ => return Err(keybox_error("unexpected certificate chain entry")),
            }
        }

        if expected.is_some_and(|expected| expected != (certificates.len() - first) as u32) {
            return Err(keybox_error("incomplete certificate chain"));
        }
        Ok(())
    }

    /// Reads the text content of a leaf element whose start tag was already consumed.
    fn leaf_text(&mut self, name: &str) -> Result<String> {
        let mut text = String::new();
        loop {
            match self.peek()? {
                XmlEvent::Text(chunk) => {
                    text.push_str(chunk);
                    self.pos += 1;
                }
                XmlEvent::End { name: closed } if closed == name => {
                    self.pos += 1;
                    return Ok(text);
                }
                _ => return Err(keybox_error(format!("unexpected element inside <{name}>"))),
            }
        }
    }
}

/// Parses an element count, rejecting anything that is not a non-negative 32-bit integer.
fn parse_count(text: &str, kind: &str) -> Result<u32> {
    let value: i64 = text
        .trim()
        .parse()
        .map_err(|_| keybox_error(format!("invalid {kind} count")))?;
    if !(0..=u32::MAX as i64).contains(&value) {
        return Err(keybox_error(format!("invalid {kind} count")));
    }
    Ok(value as u32)
}

// ---------------------------------------------------------------------------
// PEM material
// ---------------------------------------------------------------------------

/// Decodes one `<Key>`'s PEM material into its native form.
fn build_entry(private_key_text: &str, certificate_texts: &[String]) -> Result<NativeKeybox> {
    let (label, der) = pem_blocks(private_key_text)?
        .into_iter()
        .next()
        .ok_or_else(|| keybox_error("private key element has no PEM block"))?;
    let private_key_pkcs8 = normalize_private_key(&label, &der)?;
    let algorithm = key_algorithm(&private_key_pkcs8)?;

    let mut certificates = Vec::with_capacity(certificate_texts.len());
    for text in certificate_texts {
        certificates.push(decode_certificate(text)?);
    }

    Ok(NativeKeybox { algorithm, private_key_pkcs8, certificates })
}

/// Decodes every `-----BEGIN <label>-----` block in the text. The keybox material carries one key
/// block per element and one certificate block per `<Certificate>`, so only the first is used.
fn pem_blocks(text: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let lines: Vec<&str> = text.lines().collect();
    let mut blocks = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let line = lines[index].trim();
        index += 1;
        let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|rest| rest.strip_suffix("-----"))
        else {
            continue;
        };

        let end_marker = format!("-----END {label}-----");
        let mut body = String::new();
        let mut closed = false;
        while index < lines.len() {
            let body_line = lines[index].trim();
            index += 1;
            if body_line == end_marker {
                closed = true;
                break;
            }
            if body_line.starts_with("-----") {
                return Err(keybox_error("unterminated PEM block"));
            }
            body.push_str(body_line);
        }
        if !closed {
            return Err(keybox_error("unterminated PEM block"));
        }
        blocks.push((label.to_string(), base64_decode(&body)?));
    }
    Ok(blocks)
}

const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decodes standard base64, ignoring line breaks and any other whitespace.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let mut decoded = Vec::with_capacity(input.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut padded = false;

    for ch in input.chars() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        if ch == '=' {
            padded = true;
            continue;
        }
        if padded {
            return Err(keybox_error("base64 data after padding"));
        }
        let value = BASE64_ALPHABET
            .iter()
            .position(|candidate| *candidate as char == ch)
            .ok_or_else(|| keybox_error(format!("invalid base64 character {ch:?}")))? as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push(((accumulator >> bits) & 0xFF) as u8);
        }
    }

    // Any leftover bits are padding and must be zero, otherwise the input is not valid base64.
    if bits > 0 && accumulator & ((1 << bits) - 1) != 0 {
        return Err(keybox_error("base64 block has non-zero trailing bits"));
    }
    Ok(decoded)
}

/// Turns a PEM private key into PKCS#8 DER. A `PRIVATE KEY` block is already PKCS#8; the traditional
/// `EC PRIVATE KEY` (SEC1) and `RSA PRIVATE KEY` (PKCS#1) encodings are wrapped in the matching
/// `AlgorithmIdentifier` so every later native stage sees a single PKCS#8 encoding.
fn normalize_private_key(label: &str, der: &[u8]) -> Result<Vec<u8>> {
    match label {
        "PRIVATE KEY" => Ok(der.to_vec()),
        "EC PRIVATE KEY" | "ECDSA PRIVATE KEY" => wrap_sec1_key(der),
        "RSA PRIVATE KEY" => wrap_pkcs1_rsa_key(der),
        other => Err(keybox_error(format!("unsupported PEM key label: {other}"))),
    }
}

/// Wraps a SEC1 `ECPrivateKey` in a PKCS#8 envelope. The named curve has to come from the SEC1
/// parameters, since a PKCS#8 `AlgorithmIdentifier` must name the curve the key belongs to.
fn wrap_sec1_key(sec1: &[u8]) -> Result<Vec<u8>> {
    let (tag, content, total) = read_tlv(sec1)?;
    if tag != TAG_SEQUENCE || total != sec1.len() {
        return Err(keybox_error("malformed SEC1 private key"));
    }
    let elements = iter_tlvs(content)?;
    if elements.len() < 2 {
        return Err(keybox_error("malformed SEC1 private key"));
    }

    let parameters = elements
        .iter()
        .skip(2)
        .find(|element| element[0] == CONTEXT_0_CONSTRUCTED)
        .ok_or_else(|| keybox_error("SEC1 private key has no curve parameters"))?;
    let (_, parameters_content, _) = read_tlv(parameters)?;
    let (parameters_tag, _, curve_total) = read_tlv(parameters_content)?;
    if parameters_tag != TAG_OID || curve_total != parameters_content.len() {
        return Err(keybox_error("SEC1 curve parameters are not a named curve"));
    }

    let mut algorithm = encode_der_oid(OID_EC_PUBLIC_KEY);
    algorithm.extend_from_slice(&parameters_content[..curve_total]);

    let mut inner = Vec::new();
    inner.extend_from_slice(&enc_integer(0));
    inner.extend_from_slice(&enc_sequence(&algorithm));
    inner.extend_from_slice(&enc_octet_string(sec1));
    Ok(enc_sequence(&inner))
}

/// Wraps a PKCS#1 `RSAPrivateKey` in a PKCS#8 envelope with `rsaEncryption` as the algorithm.
fn wrap_pkcs1_rsa_key(pkcs1: &[u8]) -> Result<Vec<u8>> {
    let (tag, _, total) = read_tlv(pkcs1)?;
    if tag != TAG_SEQUENCE || total != pkcs1.len() {
        return Err(keybox_error("malformed PKCS#1 private key"));
    }

    let mut algorithm = encode_der_oid(OID_RSA_ENCRYPTION);
    algorithm.extend_from_slice(&[0x05, 0x00]); // NULL parameters

    let mut inner = Vec::new();
    inner.extend_from_slice(&enc_integer(0));
    inner.extend_from_slice(&enc_sequence(&algorithm));
    inner.extend_from_slice(&enc_octet_string(pkcs1));
    Ok(enc_sequence(&inner))
}

/// The algorithm of a PKCS#8 key, as the name `KeyProperties` uses. Anything other than EC or RSA
/// is rejected.
fn key_algorithm(pkcs8_der: &[u8]) -> Result<String> {
    let info = pkcs8::PrivateKeyInfo::from_der(pkcs8_der)
        .map_err(|e| keybox_error(format!("PKCS#8 parse: {e}")))?;
    let ec_oid: const_oid::ObjectIdentifier = "1.2.840.10045.2.1"
        .parse()
        .map_err(|_| keybox_error("EC algorithm OID parse"))?;
    let rsa_oid: const_oid::ObjectIdentifier = "1.2.840.113549.1.1.1"
        .parse()
        .map_err(|_| keybox_error("RSA algorithm OID parse"))?;

    if info.algorithm.oid == ec_oid {
        Ok("EC".to_string())
    } else if info.algorithm.oid == rsa_oid {
        Ok("RSA".to_string())
    } else {
        Err(keybox_error(format!("unsupported private key algorithm: {}", info.algorithm.oid)))
    }
}

/// Decodes one PEM private key block into the blob the JNI entry point returns:
/// `[u32 algorithm][u32 PKCS#8 key]`, all lengths big-endian. Kotlin rebuilds the `KeyPair` from
/// the algorithm name and the DER.
pub fn decode_key_blob(pem: &str) -> Result<Vec<u8>> {
    let (label, der) = pem_blocks(pem)?
        .into_iter()
        .next()
        .ok_or_else(|| keybox_error("private key element has no PEM block"))?;
    let pkcs8 = normalize_private_key(&label, &der)?;
    let algorithm = key_algorithm(&pkcs8)?;

    let mut blob = Vec::new();
    push_blob(&mut blob, algorithm.as_bytes());
    push_blob(&mut blob, &pkcs8);
    Ok(blob)
}

/// Decodes one certificate PEM block and checks it really is a DER certificate, matching the
/// validation the Kotlin side gets from `CertificateFactory`.
pub fn decode_certificate(text: &str) -> Result<Vec<u8>> {
    let (label, der) = pem_blocks(text)?
        .into_iter()
        .next()
        .ok_or_else(|| keybox_error("certificate element has no PEM block"))?;
    if label != "CERTIFICATE" {
        return Err(keybox_error(format!("unsupported PEM certificate label: {label}")));
    }
    Certificate::from_der(&der).map_err(|e| keybox_error(format!("certificate parse: {e}")))?;
    Ok(der)
}

fn keybox_error(message: impl Into<String>) -> CertGenError {
    CertGenError::KeyboxParseFailed(message.into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test assertions are allowed to unwrap
mod tests {
    use super::*;
    use crate::attestation::enc_explicit_tag;
    use crate::certbuilder::{build_self_signed_cert, encode_der_oid};
    use crate::keygen::generate_key_pair;
    use crate::types::{Algorithm, CertGenParams, EcCurve};

    /// The named-curve OIDs the test fixtures are built with.
    const CURVE_P256: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
    const CURVE_P384: &[u64] = &[1, 3, 132, 0, 34];

    /// Base64-encodes a DER blob the way the keybox XML carries key material.
    fn base64_encode(input: &[u8]) -> String {
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let mut buffer = [0u8; 3];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let value = ((buffer[0] as u32) << 16) | ((buffer[1] as u32) << 8) | buffer[2] as u32;
            let symbols = [
                BASE64_ALPHABET[((value >> 18) & 0x3F) as usize],
                BASE64_ALPHABET[((value >> 12) & 0x3F) as usize],
                BASE64_ALPHABET[((value >> 6) & 0x3F) as usize],
                BASE64_ALPHABET[(value & 0x3F) as usize],
            ];
            for (i, symbol) in symbols.iter().enumerate() {
                if i <= chunk.len() {
                    out.push(*symbol as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// Wraps PEM lines the way the keybox XML does, with indentation and trailing newlines.
    fn pem(label: &str, der: &[u8]) -> String {
        let encoded = base64_encode(der);
        let mut text = format!("-----BEGIN {label}-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            text.push_str(&String::from_utf8_lossy(chunk));
            text.push('\n');
        }
        text.push_str(&format!("-----END {label}-----"));
        text
    }

    /// The `privateKey` OCTET STRING of a PKCS#8 key: SEC1 for EC, PKCS#1 for RSA.
    fn pkcs8_inner(pkcs8: &[u8]) -> Vec<u8> {
        let (_, content, _) = read_tlv(pkcs8).unwrap();
        let elements = iter_tlvs(content).unwrap();
        let (_, inner, _) = read_tlv(elements[2]).unwrap();
        inner.to_vec()
    }

    /// The private scalar of a SEC1 `ECPrivateKey`.
    fn sec1_scalar(sec1: &[u8]) -> Vec<u8> {
        let (_, content, _) = read_tlv(sec1).unwrap();
        let elements = iter_tlvs(content).unwrap();
        read_tlv(elements[1]).unwrap().1.to_vec()
    }

    /// Builds the SEC1 encoding a real keybox carries: version, scalar and the named-curve
    /// parameters. The PKCS#8 that key generation emits leaves the parameters in its
    /// `AlgorithmIdentifier`, so the scalar is lifted out and put back explicitly here.
    fn sec1_blob(scalar: &[u8], curve_oid: &[u64]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&enc_integer(1));
        inner.extend_from_slice(&enc_octet_string(scalar));
        inner.extend_from_slice(&enc_explicit_tag(0, &encode_der_oid(curve_oid)));
        enc_sequence(&inner)
    }

    /// A P-256 keybox entry: the PEM key block and its self-signed certificate.
    fn ec_material() -> (String, Vec<u8>, Vec<u8>) {
        let key = generate_key_pair(Algorithm::Ec, 256, Some(EcCurve::P256), 0).unwrap();
        let params = CertGenParams { algorithm: Algorithm::Ec, key_size: 256, ..Default::default() };
        let cert = build_self_signed_cert(&key, &params).unwrap();
        let scalar = sec1_scalar(&pkcs8_inner(&key.private_key_pkcs8));
        let pem_key = pem("EC PRIVATE KEY", &sec1_blob(&scalar, CURVE_P256));
        (pem_key, scalar, cert[0].clone())
    }

    fn document(private_key_block: &str, certificates: &[&[u8]], declared: Option<usize>) -> String {
        let mut xml = String::from("<?xml version=\"1.0\"?>\n<AndroidAttestation>\n");
        xml.push_str("  <NumberOfKeyboxes>1</NumberOfKeyboxes>\n");
        xml.push_str("  <Keybox DeviceID=\"sw\">\n");
        xml.push_str("    <Key algorithm=\"ecdsa\">\n");
        xml.push_str("      <PrivateKey format=\"pem\">\n");
        xml.push_str(private_key_block);
        xml.push_str("\n      </PrivateKey>\n");
        xml.push_str("      <CertificateChain>\n");
        if let Some(count) = declared {
            xml.push_str(&format!("        <NumberOfCertificates>{count}</NumberOfCertificates>\n"));
        }
        for certificate in certificates {
            xml.push_str("        <Certificate format=\"pem\">\n");
            xml.push_str(&pem("CERTIFICATE", certificate));
            xml.push_str("\n        </Certificate>\n");
        }
        xml.push_str("      </CertificateChain>\n");
        xml.push_str("    </Key>\n  </Keybox>\n</AndroidAttestation>\n");
        xml
    }

    #[test]
    fn parses_a_well_formed_keybox() {
        let (private_key, scalar, cert) = ec_material();
        let xml = document(&private_key, &[&cert], Some(1));

        let keyboxes = parse_keybox_xml(&xml).unwrap();
        assert_eq!(keyboxes.len(), 1);
        assert_eq!(keyboxes[0].algorithm, "EC");
        assert_eq!(keyboxes[0].certificates.len(), 1);
        assert_eq!(keyboxes[0].certificates[0], cert);
        // The SEC1 key was re-wrapped: the same private scalar must come back out of the PKCS#8.
        assert_eq!(sec1_scalar(&pkcs8_inner(&keyboxes[0].private_key_pkcs8)), scalar);
        assert_eq!(key_algorithm(&keyboxes[0].private_key_pkcs8).unwrap(), "EC");
    }

    #[test]
    fn sec1_key_keeps_the_named_curve() {
        let key = generate_key_pair(Algorithm::Ec, 384, Some(EcCurve::P384), 0).unwrap();
        let scalar = sec1_scalar(&pkcs8_inner(&key.private_key_pkcs8));
        let wrapped = wrap_sec1_key(&sec1_blob(&scalar, CURVE_P384)).unwrap();

        let info = pkcs8::PrivateKeyInfo::from_der(&wrapped).unwrap();
        let curve = info.algorithm.parameters_oid().unwrap().to_string();
        assert_eq!(curve, "1.3.132.0.34", "P-384 curve OID must survive the wrap");
        assert_eq!(sec1_scalar(&pkcs8_inner(&wrapped)), scalar);
    }

    #[test]
    fn pkcs1_rsa_key_is_wrapped_into_pkcs8() {
        let key = generate_key_pair(Algorithm::Rsa, 2048, None, 65537).unwrap();
        let wrapped = wrap_pkcs1_rsa_key(&pkcs8_inner(&key.private_key_pkcs8)).unwrap();

        assert_eq!(key_algorithm(&wrapped).unwrap(), "RSA");
        assert_eq!(pkcs8_inner(&wrapped), pkcs8_inner(&key.private_key_pkcs8));
    }

    #[test]
    fn parses_the_shipped_keybox() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let keyboxes = parse_keybox_xml(include_str!("../../module/keybox.xml")).unwrap();

        assert_eq!(keyboxes.len(), 2);
        let ec = keyboxes.iter().find(|entry| entry.algorithm == "EC").unwrap();
        let rsa = keyboxes.iter().find(|entry| entry.algorithm == "RSA").unwrap();
        assert_eq!(ec.certificates.len(), 2);
        assert_eq!(rsa.certificates.len(), 2);

        // The re-wrapped EC key must be the one the shipped leaf certificate was issued for.
        let leaf = Certificate::from_der(&ec.certificates[0]).unwrap();
        let leaf_point = leaf
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let scalar = sec1_scalar(&pkcs8_inner(&ec.private_key_pkcs8));
        let derived = p256::SecretKey::from_slice(&scalar).unwrap().public_key().to_encoded_point(false);
        assert_eq!(derived.as_bytes(), leaf_point);

        // The RSA entry went through the PKCS#1 wrap and still parses back as a PKCS#8 key.
        assert_eq!(key_algorithm(&rsa.private_key_pkcs8).unwrap(), "RSA");
    }

    #[test]
    fn certificate_count_mismatch_is_rejected() {
        let (private_key, _, cert) = ec_material();
        let xml = document(&private_key, &[&cert], Some(2));
        assert!(parse_keybox_xml(&xml).is_err());
    }

    #[test]
    fn missing_private_key_is_rejected() {
        let (_, _, cert) = ec_material();
        let xml = document("", &[&cert], Some(1));
        assert!(parse_keybox_xml(&xml).is_err());
    }

    #[test]
    fn duplicate_keybox_count_is_rejected() {
        let (private_key, _, cert) = ec_material();
        let xml = document(&private_key, &[&cert], Some(1))
            .replace("<NumberOfKeyboxes>1</NumberOfKeyboxes>", "<NumberOfKeyboxes>1</NumberOfKeyboxes><NumberOfKeyboxes>1</NumberOfKeyboxes>");
        assert!(parse_keybox_xml(&xml).is_err());
    }

    #[test]
    fn unexpected_root_element_is_rejected() {
        let xml = "<Keyboxes><NumberOfKeyboxes>1</NumberOfKeyboxes></Keyboxes>";
        assert!(parse_keybox_xml(xml).is_err());
    }

    #[test]
    fn content_after_the_root_is_rejected() {
        let (private_key, _, cert) = ec_material();
        let mut xml = document(&private_key, &[&cert], Some(1));
        xml.push_str("<Keybox/>");
        assert!(parse_keybox_xml(&xml).is_err());
    }

    #[test]
    fn base64_decoding_ignores_line_breaks() {
        let bytes = [0x01u8, 0x02, 0x03, 0xFE, 0xFF];
        let encoded = base64_encode(&bytes);
        let with_breaks = format!("  {}\n\t{}  ", &encoded[..2], &encoded[2..]);
        assert_eq!(base64_decode(&with_breaks).unwrap(), bytes);
        assert!(base64_decode("!!!!").is_err());
    }

    #[test]
    fn decodes_a_standalone_pem_key_block() {
        let (private_key, scalar, _) = ec_material();
        let blob = decode_key_blob(&private_key).unwrap();

        let algorithm_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        assert_eq!(&blob[4..4 + algorithm_len], b"EC");
        let key_offset = 4 + algorithm_len;
        let key_len =
            u32::from_be_bytes([blob[key_offset], blob[key_offset + 1], blob[key_offset + 2], blob[key_offset + 3]])
                as usize;
        let pkcs8 = &blob[key_offset + 4..key_offset + 4 + key_len];
        assert_eq!(key_algorithm(pkcs8).unwrap(), "EC");
        assert_eq!(sec1_scalar(&pkcs8_inner(pkcs8)), scalar);
    }

    #[test]
    fn decodes_a_standalone_pem_certificate_block() {
        let (_, _, cert) = ec_material();
        assert_eq!(decode_certificate(&pem("CERTIFICATE", &cert)).unwrap(), cert);
        // A key block is not a certificate: the label check must reject it.
        assert!(decode_certificate(&pem("PRIVATE KEY", &cert)).is_err());
    }

    #[test]
    fn blob_encoding_lists_every_entry() {
        let (private_key, _, cert) = ec_material();
        let blob = parse_keybox_blob(&document(&private_key, &[&cert], Some(1))).unwrap();

        assert_eq!(u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]), 1);
        let algorithm_len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        assert_eq!(&blob[8..8 + algorithm_len], b"EC");
    }
    #[test]
    fn attributes_are_validated_but_never_needed() {
        // The document helper writes `DeviceID`, `algorithm` and `format` attributes; parsing must
        // succeed without ever reading them back.
        let (private_key, _, cert) = ec_material();
        let xml = document(&private_key, &[&cert], Some(1));
        assert!(xml.contains("DeviceID=\"sw\""));
        assert_eq!(parse_keybox_xml(&xml).unwrap().len(), 1);
        // A malformed attribute is still rejected, so dropping the values does not weaken the check.
        let broken = xml.replace("DeviceID=\"sw\"", "DeviceID=sw");
        assert!(parse_keybox_xml(&broken).is_err());
    }

    #[test]
    fn blob_is_allocated_at_its_exact_final_size() {
        let (private_key, _, cert) = ec_material();
        let xml = document(&private_key, &[&cert], Some(1));
        let keyboxes = parse_keybox_xml(&xml).unwrap();
        let blob = parse_keybox_blob(&xml).unwrap();
        // `blob_len` is what the response buffer is reserved with, so it must match byte for byte.
        assert_eq!(blob.len(), blob_len(&keyboxes));
        assert_eq!(blob.capacity(), blob_len(&keyboxes));
    }
}
