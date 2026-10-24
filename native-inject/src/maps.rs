//! Parser for `/proc/<pid>/maps`.
//!
//! This replaces `maps/maps.cpp`. The C++ version fed each line to `sscanf` and then walked the
//! remainder by hand; the parser below scans the same fields without trusting any of the widths,
//! because the file is kernel-generated but a truncated or unusual line still has to be skipped
//! instead of read past.

/// `PROT_READ`, as reported by the third field of a maps line.
pub const PROT_READ: u8 = 1;
/// `PROT_WRITE`, as reported by the third field of a maps line.
pub const PROT_WRITE: u8 = 2;
/// `PROT_EXEC`, as reported by the third field of a maps line.
pub const PROT_EXEC: u8 = 4;

/// One entry of the maps file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntry {
    pub start: usize,
    pub end: usize,
    /// `PROT_*` bits derived from the permission field.
    pub perms: u8,
    /// The mapping is private (`p`) rather than shared (`s`).
    pub is_private: bool,
    pub offset: usize,
    /// `dev_t` in the encoding `makedev()` produces.
    pub dev: u64,
    pub inode: u64,
    /// The file name, empty for an anonymous mapping. Not NUL-terminated.
    pub path: Vec<u8>,
}

impl MapEntry {
    /// Whether the entry is mapped from a file whose path ends with `suffix`.
    pub fn path_ends_with(&self, suffix: &[u8]) -> bool {
        self.path.len() >= suffix.len() && self.path[self.path.len() - suffix.len()..] == *suffix
    }
}

/// Which mapping of a module a lookup is after.
///
/// Two call sites need this. `find_module_base` wants the mapping that starts at the module's
/// file offset zero, i.e. the load bias; `find_module_return_addr` wants a mapping of the same
/// file that carries no execute permission, i.e. a page inside the module that can host the
/// return trampoline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleMatch {
    /// The mapping at file offset zero.
    Base,
    /// A mapping without `PROT_EXEC`.
    NonExecutable,
}

/// Whether one mapping satisfies `mode` for a module whose path ends with `suffix`.
///
/// Kept apart from the walks below so the predicate has a single definition:
/// [`find_module_start`] walks [`MapEntry`]s, while the FFI layer walks its C-facing twin and
/// calls this per entry.
pub fn matches_module(
    path: &[u8],
    offset: usize,
    perms: u8,
    suffix: &[u8],
    mode: ModuleMatch,
) -> bool {
    let suffix_ok = path.len() >= suffix.len() && path[path.len() - suffix.len()..] == *suffix;
    if !suffix_ok {
        return false;
    }
    match mode {
        ModuleMatch::Base => offset == 0,
        ModuleMatch::NonExecutable => perms & PROT_EXEC == 0,
    }
}

/// Start address of the first entry matching `mode`, or `None` when no entry does.
///
/// First match wins, which is what both C++ loops did: a module's mappings appear in ascending
/// address order, so its offset-zero mapping always precedes the rest.
pub fn find_module_start(entries: &[MapEntry], suffix: &[u8], mode: ModuleMatch) -> Option<usize> {
    entries
        .iter()
        .find(|entry| matches_module(&entry.path, entry.offset, entry.perms, suffix, mode))
        .map(|entry| entry.start)
}

/// Parses a whole maps document.
///
/// Lines that do not carry the seven standard fields are skipped, which is what the `sscanf`
/// return-value check in the C++ version did.
pub fn parse(buffer: &[u8]) -> Vec<MapEntry> {
    let mut entries = Vec::new();
    for line in buffer.split(|byte| *byte == b'\n') {
        if let Some(entry) = parse_line(line) {
            entries.push(entry);
        }
    }
    entries
}

/// Parses one line of a maps document, returning `None` when it cannot be read in full.
pub fn parse_line(line: &[u8]) -> Option<MapEntry> {
    let mut cursor = Cursor::new(line);

    let start = cursor.hex_until(b'-')?;
    let end = cursor.hex_until(b' ')?;
    cursor.skip_spaces();
    let perms_field = cursor.token()?;
    cursor.skip_spaces();
    let offset = cursor.hex_until(b' ')?;
    cursor.skip_spaces();
    let dev_field = cursor.token()?;
    cursor.skip_spaces();
    let inode = cursor.decimal_until_space()?;
    let path = cursor.rest();

    let mut perms = 0u8;
    if perms_field.first() == Some(&b'r') {
        perms |= PROT_READ;
    }
    if perms_field.get(1) == Some(&b'w') {
        perms |= PROT_WRITE;
    }
    if perms_field.get(2) == Some(&b'x') {
        perms |= PROT_EXEC;
    }

    Some(MapEntry {
        start,
        end,
        perms,
        is_private: perms_field.get(3) == Some(&b'p'),
        offset,
        dev: parse_dev(dev_field)?,
        inode,
        path: path.to_vec(),
    })
}

/// Parses a `major:minor` device number, both halves in hex, into the `dev_t` encoding.
fn parse_dev(field: &[u8]) -> Option<u64> {
    let colon = field.iter().position(|byte| *byte == b':')?;
    let major = from_hex(&field[..colon])?;
    let minor = from_hex(field.get(colon + 1..)?)?;
    // The glibc/bionic `makedev()` layout: 32 bits of major, 20 bits of minor.
    let major = major as u64;
    let minor = minor as u64;
    Some(
        ((major & 0xffff_f000) << 32)
            | ((major & 0x0000_0fff) << 8)
            | ((minor & 0xffff_f000) << 12)
            | (minor & 0x0000_00ff),
    )
}

fn from_hex(field: &[u8]) -> Option<usize> {
    if field.is_empty() {
        return None;
    }
    let mut value = 0usize;
    for byte in field {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit as usize)?;
    }
    Some(value)
}

/// Reads the fields of one line left to right, never indexing past the end.
struct Cursor<'a> {
    line: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(line: &'a [u8]) -> Self {
        Self { line, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.line.get(self.pos).copied()
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    /// Consumes hex digits up to (not including) `terminator`, then steps over the terminator.
    fn hex_until(&mut self, terminator: u8) -> Option<usize> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte == terminator {
                let value = from_hex(self.line.get(start..self.pos)?)?;
                self.pos += 1;
                return Some(value);
            }
            if byte == b' ' || byte == b'\t' {
                return None;
            }
            self.pos += 1;
        }
        None
    }

    /// Reads one whitespace-delimited token and leaves the cursor on the whitespace.
    fn token(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte == b' ' || byte == b'\t' {
                break;
            }
            self.pos += 1;
        }
        self.line.get(start..self.pos)
    }

    fn decimal_until_space(&mut self) -> Option<u64> {
        let token = self.token()?;
        if token.is_empty() {
            return None;
        }
        let mut value = 0u64;
        for byte in token {
            let digit = byte.checked_sub(b'0')?;
            if digit > 9 {
                return None;
            }
            value = value.checked_mul(10)?.checked_add(digit as u64)?;
        }
        Some(value)
    }

    /// Everything after the current position with the leading blanks removed, up to the end of
    /// the line. Trailing blanks are kept: a maps line ends with the newline that the caller
    /// already stripped, and the kernel never pads the path.
    fn rest(&mut self) -> &'a [u8] {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
        self.line.get(self.pos..).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT: &[u8] = b"\
7f8a5c0000-7f8a5c2000 r-xp 00000000 fd:01 1234 /system/lib64/libc.so
7f8a5d0000-7f8a5d1000 rw-s 00001000 08:03 42 /data/local/tmp/libinject.so
7f8a5e0000-7f8a5e1000 rw-p 00000000 00:00 0 [anon:dalvik-main space]
7f8a5f0000-7f8a5f1000 ---p 00000000 00:00 0 /dev/zero (deleted)
";

    #[test]
    fn reads_every_field_of_each_line() {
        let entries = parse(DOCUMENT);
        assert_eq!(entries.len(), 4);
        let first = &entries[0];
        assert_eq!(first.start, 0x007f_8a5c_0000);
        assert_eq!(first.end, 0x007f_8a5c_2000);
        assert_eq!(first.perms, PROT_READ | PROT_EXEC);
        assert!(first.is_private);
        assert_eq!(first.offset, 0);
        assert_eq!(first.inode, 1234);
        assert_eq!(first.path, b"/system/lib64/libc.so".to_vec());
    }

    #[test]
    fn records_shared_mappings_and_offsets() {
        let entries = parse(DOCUMENT);
        let second = &entries[1];
        assert!(!second.is_private);
        assert_eq!(second.perms, PROT_READ | PROT_WRITE);
        assert_eq!(second.offset, 0x1000);
        assert_eq!(second.path, b"/data/local/tmp/libinject.so".to_vec());
    }

    #[test]
    fn encodes_the_device_number_like_makedev() {
        let entries = parse(DOCUMENT);
        // major 0xfd, minor 0x01 -> 0xfd << 8 | 0x01
        assert_eq!(entries[0].dev, 0xfd01);
        // major 0x08, minor 0x03
        assert_eq!(entries[1].dev, 0x0803);
        // 0:0 stays zero, which is what the anonymous mappings report.
        assert_eq!(entries[2].dev, 0);
    }

    #[test]
    fn keeps_paths_with_spaces_and_without_a_trailing_newline() {
        let entries = parse(DOCUMENT);
        assert_eq!(entries[2].path, b"[anon:dalvik-main space]".to_vec());
        assert_eq!(entries[3].path, b"/dev/zero (deleted)".to_vec());
    }

    #[test]
    fn skips_lines_that_are_not_complete() {
        assert!(parse_line(b"").is_none());
        assert!(parse_line(b"garbage").is_none());
        // Missing the inode.
        assert!(parse_line(b"7f00-7f10 r-xp 00000000 fd:01 /lib.so").is_none());
        // Device field without a colon.
        assert!(parse_line(b"7f00-7f10 r-xp 00000000 fd01 42 /lib.so").is_none());
        // Non-hex start.
        assert!(parse_line(b"zz00-7f10 r-xp 00000000 fd:01 42 /lib.so").is_none());
    }

    #[test]
    fn an_empty_permission_field_leaves_every_flag_clear() {
        let entry = parse_line(b"7f00-7f10 0 00000000 fd:01 42 /lib.so").unwrap();
        assert_eq!(entry.perms, 0);
        assert!(!entry.is_private);
    }

    /// A module mapped three times, the way a real loader lays out a shared object.
    const MODULE_DOCUMENT: &[u8] = b"\
7f00-7f10 r--p 00000000 fd:01 42 /apex/com.android.runtime/lib64/bionic/libc.so
7f10-7f20 r-xp 00001000 fd:01 42 /apex/com.android.runtime/lib64/bionic/libc.so
7f20-7f30 rw-p 00002000 fd:01 42 /apex/com.android.runtime/lib64/bionic/libc.so
";

    #[test]
    fn finds_the_offset_zero_mapping_as_the_base() {
        let entries = parse(MODULE_DOCUMENT);
        assert_eq!(
            find_module_start(&entries, b"libc.so", ModuleMatch::Base),
            Some(0x7f00)
        );
    }

    #[test]
    fn base_lookup_ignores_mappings_with_a_nonzero_offset() {
        // Only a non-zero-offset mapping of `libc.so` exists, so there is no base to report.
        let entries = parse(b"7f10-7f20 r-xp 00001000 fd:01 42 /lib/libc.so\n");
        assert_eq!(
            find_module_start(&entries, b"libc.so", ModuleMatch::Base),
            None
        );
    }

    #[test]
    fn return_region_lookup_wants_a_mapping_without_exec() {
        let entries = parse(MODULE_DOCUMENT);
        assert_eq!(
            find_module_start(&entries, b"libc.so", ModuleMatch::NonExecutable),
            Some(0x7f00)
        );
        // Every mapping of the module is executable here, so nothing qualifies.
        let entries = parse(b"7f10-7f20 r-xp 00001000 fd:01 42 /lib/libc.so\n");
        assert_eq!(
            find_module_start(&entries, b"libc.so", ModuleMatch::NonExecutable),
            None
        );
    }

    #[test]
    fn lookups_need_the_whole_suffix_to_match() {
        let entries = parse(MODULE_DOCUMENT);
        assert_eq!(
            find_module_start(&entries, b"libc", ModuleMatch::Base),
            None
        );
        assert_eq!(
            find_module_start(&entries, b"bionic/libc.so", ModuleMatch::Base),
            Some(0x7f00)
        );
        assert_eq!(
            find_module_start(&entries, b"/libc.so/", ModuleMatch::Base),
            None
        );
    }

    #[test]
    fn lookups_on_an_empty_document_find_nothing() {
        assert_eq!(find_module_start(&[], b"libc.so", ModuleMatch::Base), None);
        assert_eq!(
            find_module_start(&[], b"libc.so", ModuleMatch::NonExecutable),
            None
        );
    }

    #[test]
    fn matches_the_module_suffix() {
        let entries = parse(DOCUMENT);
        assert!(entries[1].path_ends_with(b"libinject.so"));
        assert!(!entries[1].path_ends_with(b"libc.so"));
        assert!(!entries[0].path_ends_with(b"a-longer-suffix-than-the-path"));
    }

    #[test]
    fn accepts_uppercase_hex() {
        let entry = parse_line(b"7F8A-7F8B r-xp 0 FD:01 42 /lib.so").unwrap();
        assert_eq!(entry.start, 0x7f8a);
        assert_eq!(entry.offset, 0);
    }
}
