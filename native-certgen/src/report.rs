//! Log lines the native side hands back to Kotlin.
//!
//! The Rust port of the boot-time helpers replaces code that used to call `Logger` directly. It
//! cannot keep doing that: `libcertgen.so` does not link `liblog`, because the whole point of the
//! Kotlin wrapper is to report *why* the library is unusable when it fails to load. A native
//! `__android_log_print` would drag `liblog` into the dependency list and, on the failure path that
//! matters most (the .so never loads), would not run at all.
//!
//! So the native side collects its log lines as data and hands them back with the result. Kotlin
//! replays them through `Logger`, which keeps a single log sink for the whole daemon and keeps the
//! native crate free of Android-only link dependencies.
//!
//! Wire format, appended to a response blob:
//! `[u32 BE count]` followed by `count` entries of `[u8 level][u32 BE len][UTF-8 message]`.
//! The count is written even when it is zero, so the Kotlin decoder never has to guess whether the
//! section is present.

use crate::wire::Encoder;

/// Mirrors the Kotlin `Logger` levels. `Error` is not fatal: the entry point still returns a result
/// whenever it has one, exactly like the Kotlin code that logged and carried on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info = 0,
    Debug = 1,
    Warn = 2,
    Error = 3,
}

/// One log line. `message` is preformatted on the native side so the Kotlin decoder stays a plain
/// byte walk with no formatting rules to duplicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub level: Level,
    pub message: String,
}

impl Note {
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            level: Level::Info,
            message: message.into(),
        }
    }

    pub fn debug(message: impl Into<String>) -> Self {
        Self {
            level: Level::Debug,
            message: message.into(),
        }
    }

    pub fn warn(message: impl Into<String>) -> Self {
        Self {
            level: Level::Warn,
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            level: Level::Error,
            message: message.into(),
        }
    }
}

/// Appends the notes section to a response blob.
pub fn encode_notes(notes: &[Note], out: &mut Encoder) {
    out.u32(notes.len() as u32);
    for note in notes {
        out.u8(note.level as u8);
        out.text(&note.message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_are_length_prefixed_and_levelled() {
        let notes = [Note::warn("ab"), Note::info("c")];
        let mut encoder = Encoder::new();
        encode_notes(&notes, &mut encoder);
        let blob = encoder.into_vec();
        assert_eq!(
            blob,
            vec![
                0, 0, 0, 2, // count
                2, 0, 0, 0, 2, b'a', b'b', // warn
                0, 0, 0, 0, 1, b'c', // info
            ]
        );
    }

    #[test]
    fn an_empty_note_list_still_writes_the_count() {
        let mut encoder = Encoder::new();
        encode_notes(&[], &mut encoder);
        assert_eq!(encoder.into_vec(), 0u32.to_be_bytes());
    }
}
