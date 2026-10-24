//! Supervision of the injected interceptor.
//!
//! The Kotlin version ran `app_process` with the dex on the class path and hooked in-process, so
//! "starting the interceptor" meant starting a JVM and waiting for it to report success, retried
//! forever from `Main.initializeInterceptors`. The native version has no JVM to start: the interceptor
//! is a shared object that has to be mapped into the *keystore* process, and what needs supervising is
//! not our own process but the pairing between another process and our library.
//!
//! So the loop here does one thing per tick: find the platform's keystore process, and if our library
//! is not in its maps, run the injector against it. Three consequences fall out of that shape and are
//! worth stating, because they are what makes this robust across keystore restarts:
//!
//!   * The identity that matters is the library, not a PID. When keystore2 is killed and restarted —
//!     by the platform, by a crash, by `stop keystore2` — the PID changes and the maps are new, so the
//!     next tick simply injects again. Nothing tracks "did we already do this at boot".
//!   * Injection failure is not fatal. `keystore2` holds its own lock during early startup, and a
//!     `ptrace` attach that loses the race fails with `ESRCH`; the tick after it succeeds. The Kotlin
//!     loop had the same one-second cadence for the same reason.
//!   * The tick cost is one `/proc` scan per interval, which the log only sees when the state changes.
//!
//! The injector's command line is the one contract with D2: `tricky-inject <pid> <lib_path>
//! <entry_name>`. It is positional and takes three arguments, which is what
//! `app/src/main/cpp/inject/main.cpp` has always accepted; the entry name is not optional there.
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Name of the shared object the injector maps into keystore. It follows the crate's `[lib] name`
/// (`rustinject`), which is what Cargo produces as `librustinject.so`.
pub const LIBRARY_FILE: &str = "librustinject.so";

/// Symbol the injector calls once the library is mapped.
///
/// `native-inject` exports exactly one `#[no_mangle] extern "C" fn entry`, and `main.cpp` refuses to
/// run without a non-empty entry name, so this is not something the caller may omit.
pub const ENTRY_SYMBOL: &str = "entry";

/// Name of the injector binary inside the module directory.
pub const INJECTOR_FILE: &str = "tricky-inject";

/// UID the platform's keystore runs as. Checked before injecting so a user application that happens
/// to be named `keystore2` is never a target.
const KEYSTORE_UID: u32 = 1000;

/// Scan interval. One second matches the Kotlin retry cadence and keeps the boot path responsive
/// without making the scan itself noticeable.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);

/// Which process to inject into, and with what.
#[derive(Debug, Clone)]
pub struct Plan {
    /// `keystore2` on Android 12+, `keystore` on Android 10/11.
    pub process_name: &'static str,
    /// The injector binary, when one was found.
    pub injector: Option<PathBuf>,
    /// The library to map, as an absolute path when the module directory is known.
    pub library: PathBuf,
}

impl Plan {
    /// Builds the plan for this device from the module directory and the SDK level.
    ///
    /// `module_dir` is where the module's own files live (`/data/adb/modules/tricky_store`); the
    /// binaries are looked up in the layout the build produces, then in a couple of fallbacks so an
    /// unpacked dev build also works.
    pub fn discover(module_dir: &Path) -> Plan {
        let library = module_dir.join(LIBRARY_FILE);
        let injector = candidate_paths(module_dir, INJECTOR_FILE)
            .into_iter()
            .find(|path| path.is_file());
        Plan {
            process_name: target_process(sdk_level()),
            injector,
            library,
        }
    }

    /// Describes the plan in one line, for the log and `--dump`.
    pub fn describe(&self) -> String {
        format!(
            "process={} injector={} library={}",
            self.process_name,
            match &self.injector {
                Some(path) => path.display().to_string(),
                None => "not found".to_owned(),
            },
            self.library.display()
        )
    }
}

/// `keystore2` replaced the Java `keystore` service in Android 12; before that the legacy service is
/// what owns the keymaster HAL, so the two cases need different processes and different hook targets.
pub fn target_process(sdk: i32) -> &'static str {
    if sdk >= 31 {
        "keystore2"
    } else {
        "keystore"
    }
}

/// `ro.build.version.sdk`, or `0` when it cannot be read. Zero selects the legacy process, which is the
/// conservative choice: injecting into a service that is not there costs a failed attach per tick,
/// while injecting the wrong hook set into the wrong process can take the keystore down.
pub fn sdk_level() -> i32 {
    use certgen::hide_props::PropertySource;
    match certgen::system::SystemProperties.get("ro.build.version.sdk") {
        Some(value) => value.trim().parse().unwrap_or(0),
        None => 0,
    }
}

/// The outcome of one tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// The keystore process is not running (yet).
    WaitingForProcess,
    /// The process exists and already has our library mapped.
    AlreadyInjected { pid: i32 },
    /// The injector ran and reported success.
    Injected { pid: i32 },
    /// The injector existed but failed; the message is its stderr tail.
    Failed { pid: i32, error: String },
    /// No injector binary was found at all.
    NoInjector { pid: i32 },
}

impl Attempt {
    fn key(&self) -> u8 {
        match self {
            Attempt::WaitingForProcess => 0,
            Attempt::AlreadyInjected { .. } => 1,
            Attempt::Injected { .. } => 2,
            Attempt::Failed { .. } => 3,
            Attempt::NoInjector { .. } => 4,
        }
    }

    fn describe(&self) -> String {
        match self {
            Attempt::WaitingForProcess => "waiting for the keystore process".to_owned(),
            Attempt::AlreadyInjected { pid } => format!("already injected into pid {pid}"),
            Attempt::Injected { pid } => format!("injected into pid {pid}"),
            Attempt::Failed { pid, error } => format!("injection into pid {pid} failed: {error}"),
            Attempt::NoInjector { pid } => {
                format!("no injector binary, cannot attach to pid {pid}")
            }
        }
    }
}

/// One tick: resolve the target, decide whether it needs the library, inject if it does.
pub fn attempt(plan: &Plan) -> Attempt {
    let Some(pid) = find_pid(plan.process_name) else {
        return Attempt::WaitingForProcess;
    };
    if library_loaded(pid, LIBRARY_FILE) {
        return Attempt::AlreadyInjected { pid };
    }
    if let Some(uid) = uid_of(pid) {
        if uid != KEYSTORE_UID && uid != 0 {
            return Attempt::Failed {
                pid,
                error: format!("pid {pid} runs as uid {uid}, not the keystore"),
            };
        }
    }
    let Some(injector) = &plan.injector else {
        return Attempt::NoInjector { pid };
    };
    let output = Command::new(injector)
        .args(injector_arguments(pid, &plan.library))
        .output();
    match output {
        Ok(output) if output.status.success() => Attempt::Injected { pid },
        Ok(output) => Attempt::Failed {
            pid,
            error: tail(&output.stderr, &output.stdout),
        },
        Err(error) => Attempt::Failed {
            pid,
            error: error.to_string(),
        },
    }
}

/// The argv the injector is invoked with.
///
/// Split out from [`attempt`] so the contract with `main.cpp` can be asserted without a tracee and
/// without a real injector binary. The three arguments are positional and the order matters: a
/// swapped pair makes `main.cpp` read the library path as a PID and fail with "Invalid PID".
fn injector_arguments(pid: i32, library: &Path) -> [std::ffi::OsString; 3] {
    [
        std::ffi::OsString::from(pid.to_string()),
        library.as_os_str().to_owned(),
        std::ffi::OsString::from(ENTRY_SYMBOL),
    ]
}

/// Runs [`attempt`] forever, logging only when the outcome changes.
///
/// Returns only on `once` (one tick) so the caller can use it for `--dump`-style checks and tests.
/// Two consecutive identical failures are logged once: keystore2 refusing an attach during startup is
/// expected and would otherwise fill the log at one line per second.
pub fn supervise(plan: &Plan, interval: Duration, once: bool) {
    let mut last: Option<u8> = None;
    loop {
        let outcome = attempt(plan);
        let key = outcome.key();
        if last != Some(key) {
            match &outcome {
                Attempt::WaitingForProcess => {
                    crate::log::debug("Keystore process not up yet; waiting")
                }
                Attempt::AlreadyInjected { pid } => {
                    crate::log::info(format!("Interceptor present in keystore pid {pid}"))
                }
                Attempt::Injected { pid } => {
                    crate::log::info(format!("Interceptor injected into keystore pid {pid}"))
                }
                Attempt::Failed { .. } => crate::log::warn(outcome.describe()),
                Attempt::NoInjector { .. } => crate::log::error(outcome.describe()),
            }
            last = Some(key);
        }
        if once {
            return;
        }
        std::thread::sleep(interval);
    }
}

/// Finds the PID of `name` among the running processes.
///
/// `/proc/<pid>/cmdline` is checked first because the platform renames `keystore2`'s thread group
/// leader to its binary name, but an argv[0] of `/system/bin/keystore2` is equally normal; `comm` is
/// the fallback for a zombie whose cmdline is already empty.
pub fn find_pid(name: &str) -> Option<i32> {
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|text| text.parse::<i32>().ok()) else {
            continue;
        };
        if pid <= 0 {
            continue;
        }
        match std::fs::read(entry.path().join("cmdline")) {
            // A non-empty argv is authoritative: an argv[0] that is not the target means this is not
            // our process, so `comm` must not get a second chance to match something else.
            Ok(cmdline) if !cmdline.is_empty() => {
                if cmdline_matches(&cmdline, name) {
                    return Some(pid);
                }
                continue;
            }
            _ => {}
        }
        if let Some(comm) = read_file(&entry.path().join("comm")) {
            if comm.trim() == name {
                return Some(pid);
            }
        }
    }
    None
}

/// True when `soname` appears in the process's memory map.
pub fn library_loaded(pid: i32, soname: &str) -> bool {
    match read_file(&Path::new("/proc").join(pid.to_string()).join("maps")) {
        Some(maps) => maps_contain(&maps, soname),
        None => false,
    }
}

/// The process's real UID, from `/proc/<pid>/status`.
pub fn uid_of(pid: i32) -> Option<u32> {
    let status = read_file(&Path::new("/proc").join(pid.to_string()).join("status"))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn read_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Compares the first NUL-separated token of a cmdline against a process name.
fn cmdline_matches(raw: &[u8], name: &str) -> bool {
    let first = raw.split(|byte| *byte == 0).next().unwrap_or(raw);
    if first.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(first);
    match text.rsplit('/').next() {
        Some(base) => base == name,
        None => false,
    }
}

/// True when any mapped path ends in `/<soname>`.
///
/// Matching on the path component rather than on a substring matters: a library called
/// `librustinject.so.bak` or a path containing the name would otherwise read as "already injected"
/// and the daemon would never attach.
fn maps_contain(maps: &str, soname: &str) -> bool {
    let suffix = format!("/{soname}");
    maps.lines().any(|line| {
        // The path is the last field, after the six address/permission columns and any whitespace.
        match line.split_whitespace().last() {
            Some(path) => path.ends_with(&suffix),
            None => false,
        }
    })
}

/// Joins the tail of the injector's output for the log line, bounded so a chatty injector cannot
/// write megabytes into the 1 MiB log ring.
fn tail(stderr: &[u8], stdout: &[u8]) -> String {
    const MAX: usize = 300;
    let mut text = String::from_utf8_lossy(stderr).trim().to_owned();
    if text.is_empty() {
        text = String::from_utf8_lossy(stdout).trim().to_owned();
    }
    if text.is_empty() {
        return "no output".to_owned();
    }
    text = text.lines().last().unwrap_or(&text).to_owned();
    if text.len() > MAX {
        // The ellipsis is part of the budget, so the caller's bound holds for the returned string too.
        let mut cut = MAX - '…'.len_utf8();
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push('…');
    }
    text
}

/// Where a binary may live inside the module, most likely first.
fn candidate_paths(module_dir: &Path, name: &str) -> Vec<PathBuf> {
    vec![
        module_dir.join(name),
        module_dir.join("bin").join(name),
        module_dir.join("libs").join("arm64-v8a").join(name),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_process_name_follows_the_sdk_level() {
        assert_eq!(target_process(29), "keystore");
        assert_eq!(target_process(30), "keystore");
        assert_eq!(target_process(31), "keystore2");
        assert_eq!(target_process(35), "keystore2");
        assert_eq!(target_process(0), "keystore");
    }

    #[test]
    fn cmdline_matches_a_bare_and_an_absolute_name() {
        assert!(cmdline_matches(b"keystore2\0", "keystore2"));
        assert!(cmdline_matches(
            b"/system/bin/keystore2\0--flag",
            "keystore2"
        ));
        assert!(!cmdline_matches(b"keystore20\0", "keystore2"));
        assert!(!cmdline_matches(b"\0", "keystore2"));
        assert!(!cmdline_matches(b"", "keystore2"));
    }

    #[test]
    fn maps_matching_requires_the_exact_file_name() {
        let maps = "\
12c00000-12d00000 r--p 00000000 fd:05 1234 /system/lib64/librustinject.so
12d00000-12e00000 r-xp 00000000 fd:05 1234 /system/lib64/libc.so
";
        assert!(maps_contain(maps, "librustinject.so"));
        assert!(!maps_contain(maps, "libc.so.bak"));
        assert!(!maps_contain("", "librustinject.so"));
        assert!(!maps_contain(
            "12c00000-12d00000 r--p 00000000 fd:05 1234 /system/lib64/librustinject.so.bak\n",
            "librustinject.so"
        ));
    }

    #[test]
    fn the_tail_is_bounded_and_prefers_stderr() {
        assert_eq!(tail(b"boom\n", b""), "boom");
        assert_eq!(tail(b"", b"out\n"), "out");
        assert_eq!(tail(b"", b""), "no output");
        let long = "x".repeat(1000);
        let cut = tail(long.as_bytes(), b"");
        assert!(cut.len() <= 300, "got {} bytes", cut.len());
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn the_injector_receives_pid_then_library_then_entry() {
        let argv = injector_arguments(
            4242,
            Path::new("/data/adb/modules/tricky_store/librustinject.so"),
        );
        assert_eq!(argv[0], std::ffi::OsString::from("4242"));
        assert_eq!(
            argv[1],
            std::ffi::OsString::from("/data/adb/modules/tricky_store/librustinject.so")
        );
        // The C++ entry point takes three positional arguments and rejects an empty entry name, so
        // this slot cannot be dropped or reordered even though it is always the same literal.
        assert_eq!(argv[2], std::ffi::OsString::from(ENTRY_SYMBOL));
        assert_eq!(ENTRY_SYMBOL, "entry");
    }

    #[test]
    fn candidate_paths_are_ordered_module_first() {
        let paths = candidate_paths(Path::new("/data/adb/modules/tricky_store"), "tricky-inject");
        assert_eq!(
            paths[0],
            PathBuf::from("/data/adb/modules/tricky_store/tricky-inject")
        );
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn a_missing_process_is_reported_as_waiting() {
        // A process name that cannot exist on any supported system.
        let plan = Plan {
            process_name: "tricky-nonexistent-keystore-daemon",
            injector: Some(PathBuf::from("/bin/true")),
            library: PathBuf::from("/nonexistent/librustinject.so"),
        };
        assert_eq!(attempt(&plan), Attempt::WaitingForProcess);
    }
}
