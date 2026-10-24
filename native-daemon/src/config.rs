//! The three text files the daemon reads at boot.
//!
//! `target.txt`, `security_patch.txt` and `keybox.xml` are parsed by `certgen::config` and
//! `certgen::keybox_xml`, which already own the line grammar, the guards and the notes. This module
//! only decides *which* files to read, what to do when one is missing, and how the result is phrased
//! in the log — so there is one parser and two callers, not two parsers that can drift.
//!
//! Nothing here is fatal. A module that boots with no `target.txt` must come up (it simply intercepts
//! nothing); a boot that aborts because one config file has a typo is worse than one that logs it and
//! keeps the device's keystore working.
use std::path::{Path, PathBuf};

use certgen::config::{self, Mode, PatchLevels, TargetEntry};
use certgen::keybox_xml;
use certgen::report::Note;

/// Everything the control plane needs from disk.
pub struct DaemonConfig {
    /// Resolved `target.txt` entries, in file order.
    pub targets: Vec<TargetEntry>,
    /// Resolved `security_patch.txt` blocks, in file order.
    pub patch_levels: PatchLevels,
    /// What the keybox looked like, for the log and `--dump`.
    pub keybox: KeyboxState,
    /// Warnings collected while parsing, already replayed into the log.
    pub notes: Vec<Note>,
}

/// The keybox is read twice: once here, to fail loudly at boot, and again by the interceptor on the
/// attestation path, where a parse failure degrades to "leave this chain alone" instead of "refuse
/// every attestation".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyboxState {
    /// No `keybox.xml` at all: chains are left untouched.
    Missing,
    /// The file exists but holds no certificate; treated like `Missing` with a louder log line.
    Empty,
    /// The file exists but does not parse.
    Invalid(String),
    /// Parsed, with one entry per key.
    Loaded { keys: usize },
}

impl KeyboxState {
    pub fn describe(&self) -> String {
        match self {
            KeyboxState::Missing => "missing".to_owned(),
            KeyboxState::Empty => "empty".to_owned(),
            KeyboxState::Invalid(error) => format!("invalid ({error})"),
            KeyboxState::Loaded { keys } => format!("loaded ({keys} key(s))"),
        }
    }
}

/// Reads every config file under `data_dir`.
///
/// A missing file yields the empty value, never an error: `parse_targets`/`parse_patch_levels` already
/// define "no lines" as "no targets" and "no patch level overrides".
pub fn load(data_dir: &Path) -> DaemonConfig {
    let mut notes = Vec::new();

    let targets = match read_optional(&data_dir.join(config::TARGET_FILE), &mut notes) {
        Some(text) => {
            let entries = config::parse_targets(&text, &mut notes);
            crate::log::info(format!(
                "target.txt: {} target(s){}",
                entries.len(),
                summarize_modes(&entries)
            ));
            entries
        }
        None => {
            crate::log::info("target.txt: not present, no packages are targeted");
            Vec::new()
        }
    };

    let patch_levels = match read_optional(&data_dir.join(config::PATCHLEVEL_FILE), &mut notes) {
        Some(text) => {
            let levels = config::parse_patch_levels(&text, &mut notes);
            crate::log::info(format!(
                "security_patch.txt: {} block(s) ({} override(s))",
                levels.contexts.len(),
                levels.packages().count()
            ));
            levels
        }
        None => {
            crate::log::info("security_patch.txt: not present, using the device's own values");
            PatchLevels::default()
        }
    };

    let keybox = load_keybox(&data_dir.join(config::KEYBOX_FILE), &mut notes);

    crate::log::replay(&notes);

    DaemonConfig {
        targets,
        patch_levels,
        keybox,
        notes,
    }
}

impl DaemonConfig {
    /// True when `package` is listed in `target.txt`. An empty list means "everything": that is what
    /// the Kotlin loader did, and it is the only reading under which a fresh install intercepts
    /// anything before the user edits the file.
    ///
    /// The daemon never asks this question: it plans the injection once and hands the whole
    /// `target.txt` to the library. The per-package query belongs to the injection side, which has
    /// to answer "does this caller get a patched certificate" for every `generateKey` it sees, and
    /// to `--dump`-style diagnostics. Kept here because this is where the parsed list lives.
    #[allow(dead_code)]
    pub fn targets_package(&self, package: &str) -> bool {
        if self.targets.is_empty() {
            return true;
        }
        self.targets.iter().any(|entry| entry.package == package)
    }

    /// One line per aspect, for `--dump`.
    pub fn describe(&self) -> String {
        format!(
            "targets={} patch_blocks={} keybox={}",
            self.targets.len(),
            self.patch_levels.contexts.len(),
            self.keybox.describe()
        )
    }
}

fn read_optional(path: &PathBuf, notes: &mut Vec<Note>) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            notes.push(Note::warn(format!(
                "Failed to read {}: {error}",
                path.display()
            )));
            None
        }
    }
}

fn load_keybox(path: &PathBuf, notes: &mut Vec<Note>) -> KeyboxState {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::log::warn(format!(
                "{}: not present, certificate chains are left untouched",
                path.display()
            ));
            return KeyboxState::Missing;
        }
        Err(error) => {
            notes.push(Note::warn(format!(
                "Failed to read {}: {error}",
                path.display()
            )));
            return KeyboxState::Invalid(error.to_string());
        }
    };
    if text.trim().is_empty() {
        crate::log::warn(format!(
            "{}: empty, certificate chains are left untouched",
            path.display()
        ));
        return KeyboxState::Empty;
    }
    match keybox_xml::parse_keybox_xml(&text) {
        Ok(keys) if keys.is_empty() => {
            crate::log::warn(format!(
                "{}: no key in the document, certificate chains are left untouched",
                path.display()
            ));
            KeyboxState::Empty
        }
        Ok(keys) => {
            crate::log::info(format!("{}: {} key(s) parsed", path.display(), keys.len()));
            KeyboxState::Loaded { keys: keys.len() }
        }
        Err(error) => {
            crate::log::error(format!("{}: {error}", path.display()));
            KeyboxState::Invalid(error.to_string())
        }
    }
}

/// ` (2 auto, 1 leaf-hack)` — appended to the target count so the log shows what the modes were.
fn summarize_modes(entries: &[TargetEntry]) -> String {
    let auto = entries
        .iter()
        .filter(|entry| entry.mode == Mode::Auto)
        .count();
    let leaf_hack = entries
        .iter()
        .filter(|entry| entry.mode == Mode::LeafHack)
        .count();
    let generate = entries
        .iter()
        .filter(|entry| entry.mode == Mode::Generate)
        .count();
    if entries.is_empty() {
        return String::new();
    }
    format!(" ({auto} auto, {leaf_hack} leaf-hack, {generate} generate)")
}

/// Default location, for callers that do not override it.
pub fn default_data_dir() -> PathBuf {
    PathBuf::from(config::CONFIG_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tricky-config-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn a_directory_without_config_files_loads_as_empty() {
        let dir = empty_dir("empty");
        let loaded = load(&dir);
        assert!(loaded.targets.is_empty());
        assert!(loaded.patch_levels.contexts.is_empty());
        assert_eq!(loaded.keybox, KeyboxState::Missing);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn targets_and_patch_levels_are_read() {
        let dir = empty_dir("files");
        // `?` forces the leaf hack, `!` forces generation, and a bare name is AUTO. The markers may be
        // separated from the package by a space, which the Kotlin parser also accepted.
        std::fs::write(
            dir.join(config::TARGET_FILE),
            "com.example.app\ncom.example.other ?\ncom.example.third !\n",
        )
        .expect("write targets");
        std::fs::write(
            dir.join(config::PATCHLEVEL_FILE),
            "system=202501\n[vendor]\nsystem=202412\n",
        )
        .expect("write patch levels");
        let loaded = load(&dir);
        assert_eq!(loaded.targets.len(), 3);
        assert_eq!(loaded.targets[0].mode, Mode::Auto);
        assert_eq!(loaded.targets[1].package, "com.example.other");
        assert_eq!(loaded.targets[1].mode, Mode::LeafHack);
        assert_eq!(loaded.targets[2].mode, Mode::Generate);
        assert_eq!(loaded.patch_levels.contexts.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unparsable_keybox_is_reported_not_fatal() {
        let dir = empty_dir("bad-keybox");
        std::fs::write(dir.join(config::KEYBOX_FILE), "<not-a-keybox/>").expect("write keybox");
        let loaded = load(&dir);
        assert!(matches!(loaded.keybox, KeyboxState::Invalid(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_target_list_targets_every_package() {
        let dir = empty_dir("all");
        let loaded = load(&dir);
        assert!(loaded.targets_package("com.anything"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
