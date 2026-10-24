//! The JVM-free control plane.
//!
//! `Main.kt` did five things at boot, in this order, and the order is load-bearing:
//!
//!   1. load the native library          (`NativeCertGen.initialize`)
//!   2. probe the keystore for cached attestation values (`AttestUtils.probe`)
//!   3. resolve the boot key and the boot hash (`AndroidUtils.setupBootHash`)
//!   4. apply the global property spoofing (`HideProps.apply`)
//!   5. inject the interceptor and keep it alive (`initializeInterceptors`, `maintainService`)
//!
//! Steps 1 and 2 exist only because the JVM needed a library loaded before it could ask the keystore
//! anything: the probe produced the `verifiedBootKey`/`verifiedBootHash` the certificate builder then
//! reused. In the Rust daemon step 1 disappears (the parsers are ordinary code, not `dlopen`ed), and
//! step 2 turns into *reading the snapshot the interceptor observed* rather than asking keystore for
//! a throwaway key — see `probe` for why that is the better source under the patch model.
//!
//! Steps 3 and 4 are unchanged in intent. Step 3 still writes `ro.boot.vbmeta.digest` back when the
//! value did not come from the property area, because the daemon and the patched attestation have to
//! agree on the same hash. Step 4 still plans against `hide_props.txt` and runs one shell script.
//!
//! Step 5 is where the daemon differs most: the Kotlin side started a thread that retried
//! `tryRunKeystoreInterceptor` once a second forever and then parked on `Thread.join()`. The Rust
//! equivalent is a plain loop around `interceptor::attempt`, with a `--once` escape hatch so the
//! module's shell wrapper can restart it without a supervisor library.
//!
//! Usage:
//!
//! ```text
//! tricky-daemon [--data-dir DIR] [--module-dir DIR] [--dump] [--once]
//! ```

mod boot;
mod config;
mod interceptor;
mod log;
mod probe;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use certgen::hide_props;
use certgen::hide_props::ShellRunner;
use certgen::system::{ShShell, SystemProperties};

/// Read instead of `DEFAULT_DATA_DIR` when set, which keeps the tests and `--dump` runs off-device.
const DATA_DIR_ENV: &str = "TRICKY_STORE_DIR";
/// File name of the property-spoofing config, taken from the planner so the two never drift apart.
const HIDE_PROPS_NAME: &str = "hide_props.txt";

/// Where the payload reads its configuration from, inside the key store's private data directory.
///
/// The payload is loaded into `keystore2`, which runs as uid 1017, and `/data/adb` is root-only:
/// the read fails on directory permissions before SELinux is consulted. `/data/misc/keystore` is
/// `drwx------ keystore keystore` labelled `keystore_data_file`, which is exactly what the
/// `keystore` domain may read, so the daemon mirrors the payload's three inputs there and hands
/// them over. This must stay in step with `native_inject::bootstrap::MIRROR_DIR`.
const MIRROR_DIR: &str = "/data/misc/keystore/.tricky";

/// `AID_KEYSTORE`, the uid and gid `keystore2` runs as on every Android release.
const KEYSTORE_ID: u32 = 1017;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Logging may not be initialised yet, so this has to go out directly.
            eprintln!("tricky-daemon: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    if args.help {
        print!("{}", Args::USAGE);
        return Ok(());
    }

    log::init(&args.data_dir.to_string_lossy());
    log::info(format!(
        "tricky-daemon {} starting (data dir {})",
        env!("CARGO_PKG_VERSION"),
        args.data_dir.display()
    ));

    // Step 3 needs the snapshot, step 2 is what reads it, so the probe runs first even though it is
    // now just a file read.
    let snapshot = probe::probe(&args.data_dir);

    let config = config::load(&args.data_dir);
    log::replay(&config.notes);
    if args.dump {
        print!("{}", config.describe());
    } else {
        log::info(config.describe().trim_end());
    }

    let verified = boot::resolve(&args.data_dir, snapshot.as_ref());
    log::info(format!(
        "Boot key {} from {}, boot hash {} from {}",
        boot::to_hex(&verified.key),
        verified.key_source.as_str(),
        boot::to_hex(&verified.hash),
        verified.hash_source.as_str()
    ));

    apply_hide_props(&args.data_dir);
    mirror_payload_config(&args.data_dir);

    let plan = interceptor::Plan::discover(&args.module_dir);
    if args.dump {
        print!("{}", plan.describe());
        let mut out = std::io::stdout();
        // A closed pipe on `| head` is not an error worth a backtrace.
        let _ = out.flush();
        return Ok(());
    }
    log::info(plan.describe().trim_end());
    if plan.injector.is_none() {
        log::warn(format!(
            "No {} found under {}; refusing to spin on a plan that cannot work",
            interceptor::INJECTOR_FILE,
            args.module_dir.display()
        ));
        return Ok(());
    }

    interceptor::supervise(&plan, interceptor::DEFAULT_INTERVAL, args.once);
    Ok(())
}

/// Runs step 4. An absent or comment-only config is a no-op, and `hide_props::apply` already returns
/// an empty script for that case, so nothing is executed and `resetprop` is not even probed.
fn apply_hide_props(data_dir: &Path) {
    let path = data_dir.join(HIDE_PROPS_NAME);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            log::debug(format!(
                "No property config at {}; skipping the global spoofing",
                path.display()
            ));
            return;
        }
        Err(error) => {
            log::error(format!("Failed to read {}: {error}", path.display()));
            return;
        }
    };

    // The Android-backed implementations: bionic for reads, `/system/bin/sh -c` for the script.
    let outcome = hide_props::apply(&text, &SystemProperties, &ShShell);
    log::replay(&outcome.notes);
    if outcome.script.trim().is_empty() {
        log::info("Property config resolves to no changes");
        return;
    }

    // `apply` only plans; the Kotlin wrapper ran the script and so does this. Output is merged by
    // `ShShell`, and a non-zero exit yields `None` — the planner's own notes already explain each
    // skipped property, so a failing `resetprop` invocation is all that is left to report here.
    match ShShell.run(&outcome.script) {
        Some(output) => {
            let trimmed = output.trim();
            log::info(format!(
                "Applied {} property change(s), removed {}; resetprop said: {}",
                outcome.changed,
                outcome.removed,
                if trimmed.is_empty() {
                    "(nothing)"
                } else {
                    trimmed
                }
            ));
        }
        None => {
            log::warn(format!(
                "Applying {} property change(s) / {} removal(s) failed; the script ran but exited non-zero",
                outcome.changed, outcome.removed
            ));
            replay_steps(&outcome.script);
        }
    }
}

/// Copies the payload's three inputs into [`MIRROR_DIR`] and hands them to `keystore`.
///
/// Only the files that exist are copied: a device with no keybox is a supported state, and the
/// payload already treats a missing keybox as "forward every reply untouched". Failures are
/// logged and skipped rather than fatal -- the daemon's other duties (boot hash, property
/// spoofing, injection) must not be dropped because one `chown` was refused.
fn mirror_payload_config(data_dir: &Path) {
    let dir = Path::new(MIRROR_DIR);
    if let Err(error) = std::fs::create_dir_all(dir) {
        log::warn(format!("cannot create {}: {error}", dir.display()));
        return;
    }
    // The directory has to be searchable by `keystore` for the payload to reach the files inside.
    if let Err(error) = hand_to_keystore(dir, 0o700) {
        log::warn(format!(
            "cannot hand {} over to keystore: {error}",
            dir.display()
        ));
        return;
    }

    let mut copied = 0;
    for name in [
        certgen::config::KEYBOX_FILE,
        certgen::config::TEE_STATUS_FILE,
        boot::BOOT_KEY_FILE,
    ] {
        let source = data_dir.join(name);
        if !source.exists() {
            log::debug(format!("No {} to mirror", source.display()));
            continue;
        }
        let target = dir.join(name);
        if let Err(error) = std::fs::copy(&source, &target) {
            log::warn(format!(
                "cannot mirror {} to {}: {error}",
                source.display(),
                target.display()
            ));
            continue;
        }
        if let Err(error) = hand_to_keystore(&target, 0o600) {
            log::warn(format!("cannot hand {} over: {error}", target.display()));
            continue;
        }
        copied += 1;
    }
    log::info(format!(
        "Mirrored {copied} payload config file(s) into {}",
        dir.display()
    ));
}

/// Sets `mode` on `path` and gives it to `keystore`, so the injected payload can open it.
fn hand_to_keystore(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("path contains a NUL byte"))?;
    // SAFETY: `c_path` is a live NUL-terminated string for the duration of the call, and `chown`
    // only reads it.
    let result = unsafe { libc::chown(c_path.as_ptr(), KEYSTORE_ID, KEYSTORE_ID) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// How often a single `hide_props` step is retried after the combined script failed.
///
/// Ten attempts one second apart is chosen for the one command that can lose a race with the
/// framework: `/system/bin/settings` goes through the settings provider inside `system_server`, and
/// at `late_start service` that provider is not always published yet. `resetprop` writes the property
/// area directly and has no such dependency, so it succeeds on the first try.
const STEP_ATTEMPTS: u32 = 10;
const STEP_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Re-runs a failed `hide_props` script one command at a time.
///
/// `ShShell` runs the whole script through a single `sh -c`, so a non-zero exit says only that *some*
/// command failed — the exit status of `sh -c` is the status of its last command, and an earlier
/// failure is invisible. That is exactly how a working property spoof could be reported as a total
/// failure: four `resetprop` writes landed, the trailing `settings put` did not, and the log blamed
/// the script. Replaying the lines names the culprit and lets the racing command be retried.
fn replay_steps(script: &str) {
    let mut failed = 0usize;
    let mut recovered = 0usize;
    for line in script.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if run_step(line) {
            log::info(format!("hide_props: recovered '{line}'"));
            recovered += 1;
        } else {
            log::warn(format!(
                "hide_props: '{line}' still fails after {STEP_ATTEMPTS} attempts"
            ));
            failed += 1;
        }
    }
    if failed == 0 {
        log::info(format!(
            "hide_props: all {recovered} command(s) applied on replay"
        ));
    } else {
        log::warn(format!(
            "hide_props: {failed} command(s) failed, {recovered} recovered on replay"
        ));
    }
}

/// Runs one command, retrying while it may still be racing the rest of the boot.
fn run_step(line: &str) -> bool {
    for attempt in 1..=STEP_ATTEMPTS {
        if ShShell.run(line).is_some() {
            return true;
        }
        if attempt < STEP_ATTEMPTS {
            thread::sleep(STEP_RETRY_DELAY);
        }
    }
    false
}

/// Command line. Deliberately hand-rolled: four flags do not justify a parser dependency in a binary
/// that has to stay small enough to live in a Magisk module.
struct Args {
    data_dir: PathBuf,
    module_dir: PathBuf,
    dump: bool,
    once: bool,
    help: bool,
}

impl Args {
    const USAGE: &'static str = "\
Usage: tricky-daemon [OPTIONS]

  --data-dir DIR     configuration directory (default: /data/adb/tricky_store,
                     or $TRICKY_STORE_DIR)
  --module-dir DIR   module root holding the injector and the library
                     (default: inferred from the executable's location)
  --dump             print the resolved configuration and exit
  --once             make a single injection attempt instead of supervising
  -h, --help         show this text
";

    fn parse<I>(mut argv: I) -> Result<Self, String>
    where
        I: Iterator<Item = String>,
    {
        // The device path lives in `certgen::config`; repeating the literal here would let the two
        // drift the day the module moves its directory.
        let data_dir = std::env::var_os(DATA_DIR_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(config::default_data_dir);
        let mut args = Args {
            data_dir,
            module_dir: PathBuf::new(),
            dump: false,
            once: false,
            help: false,
        };
        let mut module_dir: Option<PathBuf> = None;

        while let Some(flag) = argv.next() {
            match flag.as_str() {
                "--data-dir" => args.data_dir = value(&mut argv, "--data-dir")?.into(),
                "--module-dir" => module_dir = Some(value(&mut argv, "--module-dir")?.into()),
                "--dump" => args.dump = true,
                "--once" => args.once = true,
                "-h" | "--help" => args.help = true,
                other => return Err(format!("unknown argument '{other}'\n\n{}", Args::USAGE)),
            }
        }

        args.module_dir = match module_dir {
            Some(dir) => dir,
            None => default_module_dir(),
        };
        Ok(args)
    }
}

fn value<I>(argv: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    argv.next()
        .ok_or_else(|| format!("{flag} needs a value\n\n{}", Args::USAGE))
}

/// `<module>/bin/tricky-daemon` and `<module>/tricky-daemon` are both plausible layouts, so both are
/// accepted: the module root is the parent unless the parent itself is a binary directory.
fn default_module_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let parent = exe.parent().unwrap_or(Path::new("."));
    if parent
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "bin")
        .unwrap_or(false)
    {
        return parent.parent().unwrap_or(parent).to_path_buf();
    }
    parent.to_path_buf()
}

/// Kept honest by two small tests: parsing is the one piece of the daemon that a wrong default would
/// silently break on-device (a mis-resolved module directory means the injector is never found).
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn parse(flags: &[&str]) -> Result<Args, String> {
        Args::parse(flags.iter().map(|flag| (*flag).to_owned()))
    }

    #[test]
    fn defaults_fall_back_to_the_device_paths() {
        let args = parse(&[]).expect("no flags should parse");
        assert_eq!(args.data_dir, config::default_data_dir());
        assert!(!args.dump);
        assert!(!args.once);
        assert!(!args.help);
    }

    #[test]
    fn flags_override_and_unknown_ones_are_rejected() {
        let args = parse(&["--dump", "--once", "--data-dir", "/tmp/x"]).expect("valid flags");
        assert!(args.dump && args.once);
        assert_eq!(args.data_dir, PathBuf::from("/tmp/x"));
        assert!(parse(&["--nope"]).is_err());
        assert!(parse(&["--data-dir"]).is_err());
    }

    #[test]
    fn the_hide_props_config_name_matches_the_planner() {
        // `hide_props::CONFIG_PATH` is the absolute device path; the daemon joins the file name onto
        // whatever `--data-dir` resolved to, so the two must name the same file.
        assert_eq!(
            Path::new(hide_props::CONFIG_PATH)
                .file_name()
                .and_then(|name| name.to_str()),
            Some(HIDE_PROPS_NAME)
        );
    }

    #[test]
    fn the_interval_is_the_kotlin_retry_period() {
        // `initializeInterceptors` slept 1000 ms between attempts; keeping the same value keeps the
        // injection latency after boot unchanged.
        assert_eq!(Duration::from_secs(1), interceptor::DEFAULT_INTERVAL);
    }
}
