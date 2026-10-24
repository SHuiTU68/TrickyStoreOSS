//! Parsing for the three text files the daemon reads at boot.
//!
//! `PkgConfig` used to do all of this inline: it read `target.txt` and `security_patch.txt`, ran a
//! regex over every package name, built the mode map and formatted the `tee_status` report, all from
//! a `FileObserver` callback. The parsing is the part worth testing — a malformed line must be
//! skipped with a warning instead of taking the whole table down — so it lives here as pure logic
//! with no file access at all.
//!
//! What stays in Kotlin is the part that needs Android: the inotify watcher, the binder death
//! recipient around `IPackageManager`, and the `File` handles. The wrapper hands the file's text
//! over, replays the notes through `Logger`, and swaps the freshly parsed tables into its `@Volatile`
//! fields.
//!
//! ## `target.txt`
//!
//! One package per line, `#` starts a comment. A trailing `!` forces generation, a trailing `?`
//! forces the leaf hack, and a bare name is `AUTO` — resolved per request from the live TEE probe.
//! Later lines win, matching the `LinkedHashMap` put the Kotlin version used.
//!
//! ## `security_patch.txt`
//!
//! Optional `[context]` headers, where the context is either `all` (the global default) or a package
//! name. Inside a context, `all=`, `system=`, `vendor=` and `boot=` set one partition's patch level;
//! `system`/`vendor`/`boot` fall back to `all` when unset. A context holding a single bare line is
//! shorthand for `all=<that line>`.
//!
//! Both responses carry the notes section from `report` first, then the parsed table:
//!
//! - targets: `[notes][u32 count]{ [text package][u8 mode] }`
//! - patch levels: `[notes][u32 count]{ [text context][opt text system][opt text vendor]
//!   [opt text boot][opt text all] }`, with an empty context standing for the global block.
//!
//! `text` is `[u32 BE length][UTF-8]` and `opt text` is a presence byte followed by the text when
//! present, so the Kotlin decoder is a plain byte walk.
use std::collections::HashMap;

use crate::report::{self, Note};
use crate::wire::Encoder;

/// Directory the daemon reads its config from.
pub const CONFIG_PATH: &str = "/data/adb/tricky_store";
pub const TARGET_FILE: &str = "target.txt";
pub const KEYBOX_FILE: &str = "keybox.xml";
pub const TEE_STATUS_FILE: &str = "tee_status";
pub const PATCHLEVEL_FILE: &str = "security_patch.txt";

/// Bounds on what a config file may produce, mirroring the `MAX_*` guards in `persist`: the blob
/// crosses JNI, so a hostile or corrupted file must not be able to size an allocation.
const MAX_ENTRIES: usize = 4096;
const MAX_PACKAGE_NAME_LENGTH: usize = 256;
const MAX_PATCH_VALUE_LENGTH: usize = 256;

/// How a target package is handled. The discriminants are the wire format, so they are pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Auto = 0,
    LeafHack = 1,
    Generate = 2,
}

/// One resolved `target.txt` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetEntry {
    pub package: String,
    pub mode: Mode,
}

/// One `[context]` block of `security_patch.txt`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchLevel {
    pub system: Option<String>,
    pub vendor: Option<String>,
    pub boot: Option<String>,
    pub all: Option<String>,
}

/// Every parsed block, in the order the file declared them. The empty key is the global block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchLevels {
    pub contexts: Vec<(String, PatchLevel)>,
}

impl PatchLevels {
    /// The unheaded block, which applies to every package without an override.
    pub fn global(&self) -> Option<&PatchLevel> {
        self.contexts
            .iter()
            .find(|(name, _)| name.is_empty())
            .map(|(_, level)| level)
    }

    /// The per-package overrides, i.e. everything except the global block.
    pub fn packages(&self) -> impl Iterator<Item = (&str, &PatchLevel)> {
        self.contexts
            .iter()
            .filter(|(name, _)| !name.is_empty())
            .map(|(name, level)| (name.as_str(), level))
    }
}

/// Parses `target.txt`. Invalid lines are skipped with a warning rather than failing the load: one
/// typo must not leave the device with no targets at all.
pub fn parse_targets(text: &str, notes: &mut Vec<Note>) -> Vec<TargetEntry> {
    let mut entries: Vec<TargetEntry> = Vec::new();
    for line in text.lines() {
        let raw = line.split('#').next().unwrap_or("").trim();
        if raw.is_empty() {
            continue;
        }
        // The suffix selects the mode and is then stripped; `trim` again because "com.foo !" is
        // accepted by the Kotlin parser too.
        let (mode, package) = if let Some(rest) = raw.strip_suffix('!') {
            (Mode::Generate, rest.trim())
        } else if let Some(rest) = raw.strip_suffix('?') {
            (Mode::LeafHack, rest.trim())
        } else {
            (Mode::Auto, raw)
        };
        // A second suffix means the line said "com.foo!!": only one marker is allowed, so the rest
        // is a syntax error rather than a package that happens to end in punctuation.
        if package.ends_with('!') || package.ends_with('?') || !is_package_name(package) {
            notes.push(Note::warn(format!(
                "ignoring invalid target package entry: {raw}"
            )));
            continue;
        }
        if entries.len() >= MAX_ENTRIES {
            notes.push(Note::warn(format!(
                "target.txt exceeds {MAX_ENTRIES} entries; ignoring the rest"
            )));
            break;
        }
        match entries.iter_mut().find(|entry| entry.package == package) {
            Some(existing) => existing.mode = mode,
            None => entries.push(TargetEntry {
                package: package.to_owned(),
                mode,
            }),
        }
    }
    entries
}

/// Matches `[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+`: at least two dot-separated segments,
/// each starting with a letter or underscore. Written out by hand because the crate carries no regex
/// dependency, and the pattern is small enough that a hand-written matcher is clearer than adding
/// one.
fn is_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_PACKAGE_NAME_LENGTH {
        return false;
    }
    let mut segments = 0usize;
    for segment in name.split('.') {
        let bytes = segment.as_bytes();
        match bytes.first() {
            Some(first) if first.is_ascii_alphabetic() || *first == b'_' => {}
            _ => return false,
        }
        if !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

/// Parses `security_patch.txt`. Lines outside any `[context]` header belong to the global block,
/// which is how the file has always been read: no header means the whole file is the default.
pub fn parse_patch_levels(text: &str, notes: &mut Vec<Note>) -> PatchLevels {
    // Ordered groups, mirroring the `LinkedHashMap` the Kotlin parser used: the log line reports the
    // number of overrides, and a stable order makes the response blob reproducible.
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        // A header line is consumed by the section switch and is itself not a value line.
        if let Some(name) = section_header(trimmed) {
            current = name;
            continue;
        }
        match groups.iter_mut().find(|(name, _)| *name == current) {
            Some((_, lines)) => lines.push(trimmed.to_owned()),
            None => groups.push((current.clone(), vec![trimmed.to_owned()])),
        }
    }
    let mut contexts = Vec::with_capacity(groups.len());
    for (name, lines) in groups {
        match parse_patch_context(&lines, notes) {
            Some(level) => contexts.push((name, level)),
            None => notes.push(Note::warn(format!(
                "ignoring empty patch level block: [{name}]"
            ))),
        }
    }
    PatchLevels { contexts }
}

/// Recognises a `[context]` header: the name is limited to the characters a package name, an `all`
/// keyword and the older `system`/`vendor`/`boot` aliases can be spelled with.
fn section_header(line: &str) -> Option<String> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    if inner.is_empty() {
        return None;
    }
    let allowed = inner
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.' || byte == b'-');
    if !allowed {
        return None;
    }
    Some(inner.to_owned())
}

/// Folds one block's lines into a [PatchLevel]. A single bare line is the `all=` shorthand; anything
/// else is read as `key=value`, with the last assignment for a key winning.
fn parse_patch_context(lines: &[String], notes: &mut Vec<Note>) -> Option<PatchLevel> {
    let first = lines.first()?;
    if lines.len() == 1 && !first.contains('=') {
        return Some(PatchLevel {
            all: Some(checked_value(first, notes)?),
            ..PatchLevel::default()
        });
    }
    let mut map: HashMap<String, String> = HashMap::new();
    for line in lines {
        let Some(separator) = line.find('=') else {
            notes.push(Note::warn(format!(
                "ignoring malformed patch level line: {line}"
            )));
            continue;
        };
        if separator == 0 {
            notes.push(Note::warn(format!(
                "ignoring malformed patch level line: {line}"
            )));
            continue;
        }
        let key = line[..separator].trim().to_lowercase();
        let value = line[separator + 1..].trim();
        match checked_value(value, notes) {
            Some(value) => {
                map.insert(key, value);
            }
            None => continue,
        }
    }
    if map.is_empty() {
        return None;
    }
    let all = map.get("all").cloned();
    Some(PatchLevel {
        system: map.get("system").cloned().or_else(|| all.clone()),
        vendor: map.get("vendor").cloned().or_else(|| all.clone()),
        boot: map.get("boot").cloned().or_else(|| all.clone()),
        all,
    })
}

/// Rejects an over-long or empty value. An empty `system=` is treated as "not set", because writing
/// an empty patch level would be rejected by the platform anyway.
fn checked_value(value: &str, notes: &mut Vec<Note>) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if value.len() > MAX_PATCH_VALUE_LENGTH {
        notes.push(Note::warn(format!(
            "ignoring patch level longer than {MAX_PATCH_VALUE_LENGTH} bytes"
        )));
        return None;
    }
    Some(value.to_owned())
}

/// Builds the four-line `tee_status` report. The TEE probe result is the one thing the daemon has to
/// publish for the shell scripts in `module/`, and keeping the format here means its `status=` /
/// `teeBroken=` keys are covered by a test rather than by a string literal in a `writeText` call.
pub fn format_tee_status(
    status: &str,
    category: Option<&str>,
    service_error_code: Option<i32>,
) -> String {
    // `teeBroken` is tri-state on purpose: `unknown` tells a script that the probe could not run at
    // all, which is different from "the TEE answered and it is broken".
    let tee_broken = match status {
        "AVAILABLE" => "false",
        "FAILED" => "true",
        _ => "unknown",
    };
    format!(
        "status={status}\ncategory={}\nserviceErrorCode={}\nteeBroken={tee_broken}",
        category.unwrap_or("none"),
        service_error_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "none".to_owned()),
    )
}

/// Appends the `target.txt` response: the notes section, then the mode table.
pub fn encode_targets(entries: &[TargetEntry], notes: &[Note], out: &mut Encoder) {
    report::encode_notes(notes, out);
    out.u32(entries.len() as u32);
    for entry in entries {
        out.text(&entry.package);
        out.u8(entry.mode as u8);
    }
}

/// Appends the `security_patch.txt` response: the notes section, then every context block. A `None`
/// field is written as a zero presence byte, so the decoder never has to guess whether a key was
/// present.
pub fn encode_patch_levels(levels: &PatchLevels, notes: &[Note], out: &mut Encoder) {
    report::encode_notes(notes, out);
    out.u32(levels.contexts.len() as u32);
    for (name, level) in &levels.contexts {
        out.text(name);
        for value in [&level.system, &level.vendor, &level.boot, &level.all] {
            match value {
                Some(value) => {
                    out.u8(1);
                    out.text(value);
                }
                None => {
                    out.u8(0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warn_messages(notes: &[Note]) -> Vec<&str> {
        notes.iter().map(|note| note.message.as_str()).collect()
    }

    #[test]
    fn a_bare_name_is_auto() {
        let mut notes = Vec::new();
        let entries = parse_targets("com.example.app\n", &mut notes);
        assert_eq!(
            entries,
            vec![TargetEntry {
                package: "com.example.app".to_owned(),
                mode: Mode::Auto
            }]
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn the_suffixes_select_the_mode() {
        let mut notes = Vec::new();
        let entries = parse_targets("com.example.a!\ncom.example.b?\ncom.example.c", &mut notes);
        assert_eq!(
            entries.iter().map(|entry| entry.mode).collect::<Vec<_>>(),
            vec![Mode::Generate, Mode::LeafHack, Mode::Auto]
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let mut notes = Vec::new();
        let text = "# leading comment\n\n  com.example.a  # trailing\n   \n";
        let entries = parse_targets(text, &mut notes);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].package, "com.example.a");
        assert!(notes.is_empty());
    }

    #[test]
    fn the_last_line_for_a_package_wins() {
        let mut notes = Vec::new();
        let entries = parse_targets("com.example.a!\ncom.example.a?", &mut notes);
        assert_eq!(
            entries,
            vec![TargetEntry {
                package: "com.example.a".to_owned(),
                mode: Mode::LeafHack
            }]
        );
    }

    #[test]
    fn a_single_segment_name_is_rejected() {
        let mut notes = Vec::new();
        let entries = parse_targets("nodot\ncom.example.ok\n", &mut notes);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            warn_messages(&notes),
            vec!["ignoring invalid target package entry: nodot"]
        );
    }

    #[test]
    fn a_doubled_suffix_is_rejected() {
        let mut notes = Vec::new();
        let entries = parse_targets("com.example.a!!\n", &mut notes);
        assert!(entries.is_empty());
        assert_eq!(
            warn_messages(&notes),
            vec!["ignoring invalid target package entry: com.example.a!!"]
        );
    }

    #[test]
    fn a_segment_starting_with_a_digit_is_rejected() {
        let mut notes = Vec::new();
        let entries = parse_targets("com.1example\n", &mut notes);
        assert!(entries.is_empty());
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn a_headerless_file_is_the_global_block() {
        let mut notes = Vec::new();
        let levels = parse_patch_levels("2025-01-05\n", &mut notes);
        assert_eq!(
            levels.global(),
            Some(&PatchLevel {
                system: None,
                vendor: None,
                boot: None,
                all: Some("2025-01-05".to_owned()),
            })
        );
        assert_eq!(levels.packages().count(), 0);
        assert!(notes.is_empty());
    }

    #[test]
    fn an_explicit_all_key_spells_out_the_same_thing() {
        let mut notes = Vec::new();
        let levels = parse_patch_levels("all=2025-01-05\n", &mut notes);
        assert_eq!(
            levels.global().and_then(|level| level.all.clone()),
            Some("2025-01-05".to_owned())
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn per_partition_keys_override_all() {
        let mut notes = Vec::new();
        let text = "all=2025-01-05\nsystem=2025-02-01\n";
        let levels = parse_patch_levels(text, &mut notes);
        let global = levels.global().expect("a global block");
        assert_eq!(global.all.as_deref(), Some("2025-01-05"));
        assert_eq!(global.system.as_deref(), Some("2025-02-01"));
        // `vendor` and `boot` fall back to `all`, which is what the Kotlin parser did.
        assert_eq!(global.vendor.as_deref(), Some("2025-01-05"));
        assert_eq!(global.boot.as_deref(), Some("2025-01-05"));
    }

    #[test]
    fn keys_are_lowercased_and_trimmed() {
        let mut notes = Vec::new();
        let levels = parse_patch_levels("[com.example.a]\nSYSTEM = 2025-03-01\n", &mut notes);
        let (name, level) = levels.packages().next().expect("one override");
        assert_eq!(name, "com.example.a");
        assert_eq!(level.system.as_deref(), Some("2025-03-01"));
    }

    #[test]
    fn the_global_block_and_the_overrides_are_separated() {
        let mut notes = Vec::new();
        let text = "all=2025-01-05\n\n[com.example.a]\nall=2025-04-01\n";
        let levels = parse_patch_levels(text, &mut notes);
        assert_eq!(
            levels.global().and_then(|level| level.all.clone()),
            Some("2025-01-05".to_owned())
        );
        let overrides: Vec<_> = levels.packages().collect();
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].0, "com.example.a");
        assert_eq!(overrides[0].1.all.as_deref(), Some("2025-04-01"));
    }

    #[test]
    fn a_header_with_no_lines_produces_no_block() {
        let mut notes = Vec::new();
        let levels = parse_patch_levels("[com.example.a]\n", &mut notes);
        assert_eq!(levels, PatchLevels::default());
        assert!(notes.is_empty());
    }

    #[test]
    fn a_malformed_line_inside_a_block_is_reported() {
        let mut notes = Vec::new();
        let levels = parse_patch_levels("=2025-01-05\nsystem=2025-02-01\n", &mut notes);
        assert_eq!(
            levels.global().and_then(|level| level.system.clone()),
            Some("2025-02-01".to_owned())
        );
        assert_eq!(
            warn_messages(&notes),
            vec!["ignoring malformed patch level line: =2025-01-05"]
        );
    }

    #[test]
    fn the_tee_report_keeps_its_key_names() {
        assert_eq!(
            format_tee_status("AVAILABLE", None, None),
            "status=AVAILABLE\ncategory=none\nserviceErrorCode=none\nteeBroken=false"
        );
        assert_eq!(
            format_tee_status("FAILED", Some("KEYSTORE"), Some(-8)),
            "status=FAILED\ncategory=KEYSTORE\nserviceErrorCode=-8\nteeBroken=true"
        );
        assert_eq!(
            format_tee_status("UNAVAILABLE", None, None),
            "status=UNAVAILABLE\ncategory=none\nserviceErrorCode=none\nteeBroken=unknown"
        );
    }

    #[test]
    fn the_target_blob_carries_notes_then_entries() {
        let mut notes = Vec::new();
        let entries = parse_targets("com.example.a!\n", &mut notes);
        notes.push(Note::info("loaded"));
        let mut encoder = Encoder::new();
        encode_targets(&entries, &notes, &mut encoder);
        let blob = encoder.into_vec();
        let mut expected = Vec::new();
        expected.extend_from_slice(&1u32.to_be_bytes()); // one note
        expected.push(0); // info
        expected.extend_from_slice(&6u32.to_be_bytes());
        expected.extend_from_slice(b"loaded");
        expected.extend_from_slice(&1u32.to_be_bytes()); // one entry
        expected.extend_from_slice(&13u32.to_be_bytes());
        expected.extend_from_slice(b"com.example.a");
        expected.push(Mode::Generate as u8);
        assert_eq!(blob, expected);
    }

    #[test]
    fn an_absent_patch_key_is_a_zero_presence_byte() {
        let levels = PatchLevels {
            contexts: vec![(
                String::new(),
                PatchLevel {
                    system: None,
                    vendor: Some("v".to_owned()),
                    boot: None,
                    all: None,
                },
            )],
        };
        let mut encoder = Encoder::new();
        encode_patch_levels(&levels, &[], &mut encoder);
        let blob = encoder.into_vec();
        let mut expected = Vec::new();
        expected.extend_from_slice(&0u32.to_be_bytes()); // no notes
        expected.extend_from_slice(&1u32.to_be_bytes()); // one block
        expected.extend_from_slice(&0u32.to_be_bytes()); // empty context name
        expected.push(0); // system absent
        expected.push(1); // vendor present
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(b"v");
        expected.push(0); // boot absent
        expected.push(0); // all absent
        assert_eq!(blob, expected);
    }
}
