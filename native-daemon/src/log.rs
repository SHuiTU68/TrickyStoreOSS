//! Single log sink for the daemon.
//!
//! The Kotlin daemon logged through `Logger`, which wrote to logcat *and* to a file under the data
//! directory. The Rust daemon has no JVM, so the sink is built here directly on top of three
//! primitives: `liblog` on Android, a line-buffered file under `/data/adb/tricky_store`, and stderr
//! when neither is available (host builds and `--dump` runs).
//!
//! Ordering matters: a log line must never be able to abort the daemon. Every write failure is
//! swallowed, exactly like the Kotlin sink that ignored a failed `File.appendText`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use certgen::report::{Level, Note};

/// Rotation threshold: one boot's worth of log lines is a few tens of kilobytes, so a megabyte is
/// roughly a hundred boots. Past that the old file is replaced instead of grown.
const MAX_LOG_BYTES: u64 = 1 << 20;

struct Sink {
    file: Option<Mutex<File>>,
}

static SINK: OnceLock<Sink> = OnceLock::new();

/// Opens the log file. Called once from `main`; a second call is a no-op.
pub fn init(data_dir: &str) {
    let path = Path::new(data_dir).join("daemon.log");
    let file = open_rotated(&path);
    let _ = SINK.set(Sink {
        file: file.map(Mutex::new),
    });
}

fn open_rotated(path: &Path) -> Option<File> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0) > MAX_LOG_BYTES {
        // Rename-then-create: a crash between the two leaves the previous log recoverable as `.old`
        // and the live path missing, which the next start simply creates again.
        let _ = std::fs::rename(path, path.with_extension("log.old"));
    }
    OpenOptions::new().create(true).append(true).open(path).ok()
}

pub fn log(level: Level, message: &str) {
    let tag = match level {
        Level::Info => "I",
        Level::Debug => "D",
        Level::Warn => "W",
        Level::Error => "E",
    };
    let line = format!("[{}][{}] {}\n", epoch_seconds(), tag, message);
    if let Some(sink) = SINK.get() {
        if let Some(file) = &sink.file {
            if let Ok(mut file) = file.lock() {
                let _ = file.write_all(line.as_bytes());
            }
        }
    } else {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
    logcat(level, message);
}

/// Replays the notes the `certgen` planners hand back, so a parsed warning reaches the same sink the
/// Kotlin daemon used.
pub fn replay(notes: &[Note]) {
    for note in notes {
        log(note.level, &note.message);
    }
}

pub fn info(message: impl AsRef<str>) {
    log(Level::Info, message.as_ref());
}

pub fn debug(message: impl AsRef<str>) {
    log(Level::Debug, message.as_ref());
}

pub fn warn(message: impl AsRef<str>) {
    log(Level::Warn, message.as_ref());
}

pub fn error(message: impl AsRef<str>) {
    log(Level::Error, message.as_ref());
}

fn epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(target_os = "android")]
fn logcat(level: Level, message: &str) {
    use std::ffi::{c_char, CString};

    extern "C" {
        fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
    }

    // liblog priorities: 3 = DEBUG, 4 = INFO, 5 = WARN, 6 = ERROR.
    let prio = match level {
        Level::Debug => 3,
        Level::Info => 4,
        Level::Warn => 5,
        Level::Error => 6,
    };
    let Ok(tag) = CString::new("TrickyStoreOSS") else {
        return;
    };
    let Ok(text) = CString::new(message) else {
        return;
    };
    // SAFETY: both pointers reference NUL-terminated buffers that outlive the call, which is the
    // entire contract of `__android_log_write`.
    unsafe {
        __android_log_write(prio, tag.as_ptr(), text.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
fn logcat(_level: Level, _message: &str) {}
