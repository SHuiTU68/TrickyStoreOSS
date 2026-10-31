//! Boot-time, global system-property spoofing.
//!
//! `ro.*` properties are read-only once init has set them, so a plain `SystemProperties.set`
//! silently fails. Every write here therefore goes through `resetprop -n`, which edits the shared
//! property area in place and bypasses `property_service` (so no `on property:` events fire).
//!
//! Two rules keep the write invisible to property-area tamper checks:
//!   - Only properties that already exist on this build are rewritten. Inserting a brand-new entry
//!     takes a write fault on a fresh property-area page, which moves the area's mtime and leaves a
//!     property the build never defined (e.g. `sys.oem_unlock_allowed` on Android 16+). Both are
//!     recorded as tamper evidence, so a missing property is skipped instead of created.
//!   - In-place rewrites of existing entries normally leave the area mtime untouched.
//!
//! A line with no `=` is a removal directive instead of an assignment: the property is deleted from
//! the area altogether. Some keys cannot be spoofed at all because the only safe state is "absent" —
//! `sys.oem_unlock_allowed` is one of them. `frameworks/base` stopped writing it in Android 16, so a
//! build that still exposes it was written by something outside the platform, and detectors treat
//! any non-empty value as evidence of tampering rather than checking the value itself.
//!
//! The whole config is resolved once at startup and applied in a single shell invocation: properties
//! whose value already matches are skipped outright, so the cost is a couple of fork/execs per boot
//! and the keystore hot path stays untouched.
//!
//! This module is pure logic: property reads, shell execution and logging all go through the small
//! traits below, so the planner can be exercised on a host build without a device. `system` provides
//! the Android-backed implementations, and `lib` packs the result into the JNI response blob.

use std::collections::HashMap;

use crate::report::Note;

/// Where the config lives. Read by the Kotlin wrapper, which hands the text over as an argument.
pub const CONFIG_PATH: &str = "/data/adb/tricky_store/hide_props.txt";

// Keys without a dot are behaviour switches, not properties.
const ADB_KEY: &str = "adb";
const USB_KEY: &str = "usb";
const FINGERPRINT_KEY: &str = "fp";
const SHELL: &str = "/system/bin/sh";
const SETTINGS: &str = "/system/bin/settings";

const USB_PROPERTIES: [&str; 3] = ["sys.usb.config", "persist.sys.usb.config", "sys.usb.state"];

/// Every build fingerprint a device can expose, paired with the property prefix that holds that
/// partition's own product identity. `ro.build.fingerprint` belongs to the system partition.
const FINGERPRINT_PROPERTIES: [(&str, &str); 7] = [
    ("ro.build.fingerprint", "ro.product"),
    ("ro.system.build.fingerprint", "ro.product.system"),
    ("ro.system_ext.build.fingerprint", "ro.product.system_ext"),
    ("ro.vendor.build.fingerprint", "ro.product.vendor"),
    ("ro.odm.build.fingerprint", "ro.product.odm"),
    ("ro.product.build.fingerprint", "ro.product.product"),
    ("ro.bootimage.build.fingerprint", "ro.product.bootimage"),
];

const RESETPROP_CANDIDATES: [&str; 4] = [
    "resetprop",
    "/data/adb/magisk/resetprop",
    "/data/adb/ksu/bin/resetprop",
    "/data/adb/ap/bin/resetprop",
];

/// Reads a system property. `None` means the build does not define it at all, which is different
/// from "defines it as the empty string": the planner skips the former and rewrites the latter.
pub trait PropertySource {
    fn get(&self, name: &str) -> Option<String>;
}

/// Runs a shell script through `/system/bin/sh -c` and returns its merged output, or `None` when the
/// script exits non-zero (the Kotlin original treated a failed `sh` the same way).
pub trait ShellRunner {
    fn run(&self, script: &str) -> Option<String>;
}

/// One `hide_props.txt` line: a `Some(value)` assigns, a `None` deletes the property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub value: Option<String>,
}

/// What the planner decided to do, plus the log lines to replay and the script to execute.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub script: String,
    /// Properties rewritten (assignments plus fingerprint rewrites), mirroring the Kotlin counter.
    pub changed: usize,
    /// Properties deleted.
    pub removed: usize,
    pub notes: Vec<Note>,
}

/// Applies the global spoofing once at boot. Empty or comment-only configs are a no-op: nothing is
/// executed and `resetprop` is not even probed.
pub fn apply(text: &str, props: &dyn PropertySource, shell: &dyn ShellRunner) -> Outcome {
    let mut notes = Vec::new();
    let entries = parse_config(text, &mut notes);
    let mut outcome = Outcome {
        notes,
        ..Outcome::default()
    };
    if entries.is_empty() {
        return outcome;
    }

    let resetprop = locate_resetprop(shell);
    // The assignments the config is about to make, so the fingerprint chain can be composed from
    // the values the device will report *after* this run rather than the ones it reports now.
    let mut configured: HashMap<String, String> = HashMap::new();
    let mut spoof_fingerprint = false;
    let mut script = String::new();

    for entry in &entries {
        let name = entry.name.as_str();
        let value = match &entry.value {
            None => {
                let removed = append_remove(
                    &mut script,
                    name,
                    resetprop.as_deref(),
                    props,
                    &mut outcome.notes,
                );
                outcome.removed += removed;
                continue;
            }
            Some(value) => value,
        };
        if name.eq_ignore_ascii_case(ADB_KEY) {
            append_adb(&mut script, value, &mut outcome.notes);
        } else if name.eq_ignore_ascii_case(USB_KEY) {
            append_usb(
                &mut script,
                value,
                resetprop.as_deref(),
                props,
                &mut outcome.notes,
            );
        } else if name.eq_ignore_ascii_case(FINGERPRINT_KEY) {
            spoof_fingerprint = parse_switch(value, FINGERPRINT_KEY, &mut outcome.notes);
        } else if name.contains('.') {
            let current = props.get(name);
            match (resetprop.as_deref(), current) {
                (None, _) => outcome.notes.push(Note::error(format!(
                    "resetprop not found; cannot spoof '{name}'"
                ))),
                // Skip a property this build never defined: creating it inserts a new entry
                // (fresh-page write fault -> mtime moves) and leaves a non-AOSP property that
                // tamper checks flag. Rewriting an existing entry is the only safe edit.
                (Some(_), None) => outcome.notes.push(Note::debug(format!(
                    "skipping '{name}': not defined on this device"
                ))),
                (Some(path), Some(current)) => {
                    // Record only what this build can actually report: a skipped assignment must
                    // not leak into the fingerprint chain, or the composed fingerprint would
                    // advertise an identity the device never had.
                    configured.insert(name.to_owned(), value.clone());
                    if current != *value {
                        script.push_str(&resetprop_command(path, name, value));
                        outcome.changed += 1;
                    }
                }
            }
        } else {
            outcome.notes.push(Note::warn(format!(
                "ignoring unknown hide_props key: '{name}'"
            )));
        }
    }

    // Composed last: every fingerprint is derived from the product identity this run is about to
    // install, so the chain describes the device the rest of the config just built.
    if spoof_fingerprint {
        if let Some(path) = resetprop.as_deref() {
            let rewritten =
                append_fingerprints(&mut script, &configured, props, path, &mut outcome.notes);
            outcome.changed += rewritten;
        }
    }

    if !script.is_empty() {
        outcome.notes.push(Note::info(format!(
            "Applying boot property spoofing ({} properties changed, {} removed)",
            outcome.changed, outcome.removed
        )));
        shell.run(&script);
    }
    outcome.script = script;
    outcome
}

/// Sets a single property through `resetprop`; returns false when it could not be applied.
pub fn set_property(
    name: &str,
    value: &str,
    props: &dyn PropertySource,
    shell: &dyn ShellRunner,
) -> bool {
    if props.get(name).as_deref() == Some(value) {
        return true;
    }
    match locate_resetprop(shell) {
        Some(path) => shell.run(&resetprop_command(&path, name, value)).is_some(),
        None => false,
    }
}

fn resetprop_command(resetprop: &str, name: &str, value: &str) -> String {
    format!(
        "{} -n {} {}\n",
        shell_quote(resetprop),
        shell_quote(name),
        shell_quote(value)
    )
}

fn append_adb(script: &mut String, value: &str, notes: &mut Vec<Note>) {
    if !value.eq_ignore_ascii_case("off") && !value.eq_ignore_ascii_case("disable") && value != "0"
    {
        notes.push(Note::warn(format!(
            "hide_props: unsupported adb value '{value}' (expected 'off')"
        )));
        return;
    }
    script.push_str(&adb_disable_script(SETTINGS));
}

/// How long the retry loop waits for the settings provider, one `put`+`get` attempt per second.
const ADB_DISABLE_BUDGET: u32 = 30;

/// The `adb=off` applier: a detached retry loop, not a single `settings put`.
///
/// The settings provider lives in system_server, which is usually still coming up when the daemon
/// reaches this script from service.sh. A one-shot `settings put` loses that race, exits non-zero
/// and its output is discarded by the runner — the toggle is simply still on after boot. That is
/// the "adb=off stopped working" report, and it is invisible because every other key in this file
/// goes through `resetprop`, which needs no provider at all.
///
/// So the loop keeps `put`-ing once a second until a `get` reads the value back as `0`, and emits
/// one greppable line through the `log` binary when the budget runs out. The whole block runs
/// detached — `( ... ) >/dev/null 2>&1 &` — because the caller executes this script synchronously
/// on the daemon boot path, ahead of the forge socket: waiting out system_server here would delay
/// every keystore request arriving in the meantime. The redirects also close the inherited stdout
/// pipe, so the runner's reader sees EOF as soon as the foreground script ends instead of waiting
/// out the retry budget.
fn adb_disable_script(settings: &str) -> String {
    format!(
        r#"(
  i=0
  while [ "$i" -lt {budget} ]; do
    {settings} put global adb_enabled 0 >/dev/null 2>&1
    [ "$({settings} get global adb_enabled 2>/dev/null)" = 0 ] && break
    i=$((i+1))
    sleep 1
  done
  [ "$({settings} get global adb_enabled 2>/dev/null)" = 0 ] ||
    /system/bin/log -t TrickyStoreOSS "hide_props: adb=off unconfirmed after {budget}s; settings provider never answered"
) >/dev/null 2>&1 &
"#,
        settings = settings,
        budget = ADB_DISABLE_BUDGET
    )
}

/// Rewrites the three USB config properties.
///
/// `setprop` is unusable here: `sys.usb.config` is owned by init's `on property:` triggers, so
/// writing it notifies property_service, fires those triggers and reconfigures the gadget — exactly
/// the transition a detector watches for. `resetprop -n` edits the property area in place without
/// notifying property_service, which is how every other key in this file is spoofed. Entries this
/// build never defined are skipped for the mtime/fresh-page reason documented above;
/// `sys.usb.state` only exists once a gadget function is bound.
fn append_usb(
    script: &mut String,
    value: &str,
    resetprop: Option<&str>,
    props: &dyn PropertySource,
    notes: &mut Vec<Note>,
) {
    if value.is_empty() {
        return;
    }
    let Some(resetprop) = resetprop else {
        notes.push(Note::error(
            "resetprop not found; cannot spoof usb config".to_owned(),
        ));
        return;
    };
    for name in USB_PROPERTIES {
        if props.get(name).is_none() {
            notes.push(Note::debug(format!(
                "skipping '{name}': not defined on this device"
            )));
        } else {
            script.push_str(&resetprop_command(resetprop, name, value));
        }
    }
}

/// Deletes a property from the area entirely (`hide_props.txt` line without `=`).
///
/// Used for keys whose only safe state is non-existence: rewriting the value cannot help because
/// the check is "does this property exist", not "what does it hold". An absent key is skipped, so a
/// second boot on an already-clean device is a no-op and cannot move the area mtime.
///
/// Returns 1 when a delete command was emitted, 0 when the key was already absent.
fn append_remove(
    script: &mut String,
    name: &str,
    resetprop: Option<&str>,
    props: &dyn PropertySource,
    notes: &mut Vec<Note>,
) -> usize {
    if !name.contains('.') {
        notes.push(Note::warn(format!(
            "hide_props: '{name}' has no value and is not a property name; ignoring"
        )));
        return 0;
    }
    let Some(resetprop) = resetprop else {
        notes.push(Note::error(format!(
            "resetprop not found; cannot remove '{name}'"
        )));
        return 0;
    };
    if props.get(name).is_none() {
        return 0;
    }
    script.push_str(&format!(
        "{} --delete {}\n",
        shell_quote(resetprop),
        shell_quote(name)
    ));
    1
}

/// Rebuilds every `ro.*.build.fingerprint` from the device's own product identity.
///
/// A fingerprint is not a free-form string: it is `brand/product/device:release/id/incremental:
/// type/tags`, and a detector can cross-check each segment against the `ro.product.*` properties it
/// claims to describe. Hard-coding some other device's fingerprint therefore *creates* the
/// inconsistency it was meant to hide, so the value is composed here instead — from the very
/// properties this run just installed. The result is by construction self-consistent, and it only
/// differs from what the build shipped when the config actually changed the product identity.
///
/// Returns the number of fingerprint properties rewritten.
fn append_fingerprints(
    script: &mut String,
    configured: &HashMap<String, String>,
    props: &dyn PropertySource,
    resetprop: &str,
    notes: &mut Vec<Note>,
) -> usize {
    // The build identity half of the fingerprint is shared by every partition.
    let Some(release) = effective(configured, props, "ro.build.version.release") else {
        return missing_build_identity(notes);
    };
    let Some(id) = effective(configured, props, "ro.build.id") else {
        return missing_build_identity(notes);
    };
    let Some(incremental) = effective(configured, props, "ro.build.version.incremental") else {
        return missing_build_identity(notes);
    };
    let Some(build_type) = effective(configured, props, "ro.build.type") else {
        return missing_build_identity(notes);
    };
    let Some(tags) = effective(configured, props, "ro.build.tags") else {
        return missing_build_identity(notes);
    };

    let mut rewritten = 0;
    for (fingerprint_property, product_prefix) in FINGERPRINT_PROPERTIES {
        let brand = effective(configured, props, &format!("{product_prefix}.brand"));
        let product = effective(configured, props, &format!("{product_prefix}.name"));
        let device = effective(configured, props, &format!("{product_prefix}.device"));
        let (Some(brand), Some(product), Some(device)) = (brand, product, device) else {
            notes.push(Note::debug(format!(
                "skipping '{fingerprint_property}': '{product_prefix}.*' is incomplete"
            )));
            continue;
        };
        let current = props.get(fingerprint_property);
        let composed =
            format!("{brand}/{product}/{device}:{release}/{id}/{incremental}:{build_type}/{tags}");
        match current {
            // Same rule as every other key in this file: never create an entry the build did not
            // define, and never rewrite one that already holds the right value.
            None => notes.push(Note::debug(format!(
                "skipping '{fingerprint_property}': not defined on this device"
            ))),
            Some(current) if current == composed => {}
            Some(_) => {
                script.push_str(&resetprop_command(
                    resetprop,
                    fingerprint_property,
                    &composed,
                ));
                rewritten += 1;
            }
        }
    }
    rewritten
}

fn missing_build_identity(notes: &mut Vec<Note>) -> usize {
    notes.push(Note::warn(
        "skipping fingerprint chain: the build identity properties are incomplete".to_owned(),
    ));
    0
}

/// Reads the value a property will hold after this run: a pending assignment from the config wins
/// over the live value, because the live one is what is being replaced. An empty live value counts
/// as unset, matching the Kotlin `takeIf { it.isNotEmpty() }`.
fn effective(
    configured: &HashMap<String, String>,
    props: &dyn PropertySource,
    name: &str,
) -> Option<String> {
    if let Some(value) = configured.get(name) {
        return Some(value.clone());
    }
    props.get(name).filter(|value| !value.is_empty())
}

/// Parses the on/off style behaviour switches (`adb`, `usb`, `fp`).
fn parse_switch(value: &str, key: &str, notes: &mut Vec<Note>) -> bool {
    match value.to_lowercase().as_str() {
        "on" | "true" | "1" | "yes" | "enable" | "enabled" => true,
        "off" | "false" | "0" | "no" | "disable" | "disabled" => false,
        _ => {
            notes.push(Note::warn(format!(
                "hide_props: unsupported {key} value '{value}' (expected 'on' or 'off')"
            )));
            false
        }
    }
}

fn parse_config(text: &str, notes: &mut Vec<Note>) -> Vec<Entry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let entry = line.split('#').next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        match entry.find('=') {
            // A name with no `=` is a removal directive: delete the property, do not set it.
            None => entries.push(Entry {
                name: entry.to_owned(),
                value: None,
            }),
            Some(0) => notes.push(Note::warn(format!(
                "ignoring malformed hide_props line: {line}"
            ))),
            Some(separator) => {
                let name = entry[..separator].trim();
                if name.is_empty() {
                    continue;
                }
                let value = entry[separator + 1..].trim();
                entries.push(Entry {
                    name: name.to_owned(),
                    value: Some(value.to_owned()),
                });
            }
        }
    }
    entries
}

/// Finds `resetprop` once per run: a shell builtin-free `command -v` walk over the usual locations,
/// in the same order the Kotlin code used.
fn locate_resetprop(shell: &dyn ShellRunner) -> Option<String> {
    let mut script = String::from("for c in");
    for candidate in RESETPROP_CANDIDATES {
        script.push(' ');
        script.push_str(&shell_quote(candidate));
    }
    script.push_str(
        "; do if command -v \"$c\" >/dev/null 2>&1; then printf '%s' \"$c\"; exit 0; fi; done; exit 1",
    );
    shell
        .run(&script)
        .map(|output| output.trim().to_owned())
        .filter(|output| !output.is_empty())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The interpreter every script is handed to. Kept here so the trait carries the contract, and the
/// Android implementation in `system` only has to spawn it.
pub const INTERPRETER: &str = SHELL;

#[cfg(test)]
mod tests {
    use super::*;

    /// Property table double. An empty value folds to `None`, matching "not defined on this build"
    /// as `SystemProperties.get(name, null)` reports it.
    struct FakeProperties {
        values: HashMap<String, String>,
    }

    impl FakeProperties {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self {
                values: pairs
                    .iter()
                    .filter(|(_, value)| !value.is_empty())
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
            }
        }
    }

    impl PropertySource for FakeProperties {
        fn get(&self, name: &str) -> Option<String> {
            self.values.get(name).cloned()
        }
    }

    /// Records every script and answers the `resetprop` probe with a fixed path.
    struct FakeShell {
        scripts: std::cell::RefCell<Vec<String>>,
        locate: Option<String>,
        ok: bool,
    }

    impl FakeShell {
        fn with_resetprop(path: &str) -> Self {
            Self {
                scripts: std::cell::RefCell::new(Vec::new()),
                locate: Some(path.to_owned()),
                ok: true,
            }
        }

        fn without_resetprop() -> Self {
            Self {
                scripts: std::cell::RefCell::new(Vec::new()),
                locate: None,
                ok: true,
            }
        }

        fn scripts(&self) -> Vec<String> {
            self.scripts.borrow().clone()
        }

        /// The script that actually applies the plan (the probe always runs first).
        fn plan(&self) -> String {
            self.scripts().last().cloned().unwrap_or_default()
        }
    }

    impl ShellRunner for FakeShell {
        fn run(&self, script: &str) -> Option<String> {
            self.scripts.borrow_mut().push(script.to_owned());
            if script.contains("command -v") {
                return self.locate.clone();
            }
            if self.ok {
                Some(String::new())
            } else {
                None
            }
        }
    }

    fn notes_of(outcome: &Outcome, level: crate::report::Level) -> Vec<String> {
        outcome
            .notes
            .iter()
            .filter(|note| note.level == level)
            .map(|note| note.message.clone())
            .collect()
    }

    #[test]
    fn an_empty_config_runs_nothing() {
        let props = FakeProperties::new(&[("ro.build.id", "AP1A")]);
        let shell = FakeShell::with_resetprop("/data/adb/magisk/resetprop");
        let outcome = apply("", &props, &shell);
        assert_eq!(outcome, Outcome::default());
        assert!(shell.scripts().is_empty());
    }

    #[test]
    fn a_defined_property_is_rewritten_in_place() {
        let props = FakeProperties::new(&[("ro.debuggable", "1")]);
        let shell = FakeShell::with_resetprop("/data/adb/magisk/resetprop");
        let outcome = apply("ro.debuggable=0\n", &props, &shell);
        assert_eq!(outcome.changed, 1);
        assert_eq!(outcome.removed, 0);
        assert_eq!(
            outcome.script,
            "'/data/adb/magisk/resetprop' -n 'ro.debuggable' '0'\n"
        );
        assert_eq!(shell.scripts().len(), 2, "one probe plus one plan");
        assert_eq!(notes_of(&outcome, crate::report::Level::Info).len(), 1);
    }

    #[test]
    fn an_undefined_property_is_skipped_with_a_debug_note() {
        let props = FakeProperties::new(&[]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("ro.unknown=1\n", &props, &shell);
        assert_eq!(outcome.changed, 0);
        assert!(outcome.script.is_empty());
        assert_eq!(
            notes_of(&outcome, crate::report::Level::Debug),
            vec!["skipping 'ro.unknown': not defined on this device".to_owned()]
        );
    }

    #[test]
    fn a_property_that_already_holds_the_value_is_not_rewritten() {
        let props = FakeProperties::new(&[("ro.debuggable", "0")]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("ro.debuggable = 0\n", &props, &shell);
        assert_eq!(outcome.changed, 0);
        assert!(outcome.script.is_empty());
        assert_eq!(shell.scripts().len(), 1, "only the probe ran");
    }

    #[test]
    fn a_missing_resetprop_is_reported_per_property() {
        let props = FakeProperties::new(&[("ro.debuggable", "1")]);
        let shell = FakeShell::without_resetprop();
        let outcome = apply("ro.debuggable=0\n", &props, &shell);
        assert_eq!(outcome.changed, 0);
        assert_eq!(
            notes_of(&outcome, crate::report::Level::Error),
            vec!["resetprop not found; cannot spoof 'ro.debuggable'".to_owned()]
        );
    }

    #[test]
    fn a_line_without_a_value_deletes_the_property() {
        let props = FakeProperties::new(&[("sys.oem_unlock_allowed", "1")]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("sys.oem_unlock_allowed\n", &props, &shell);
        assert_eq!(outcome.removed, 1);
        assert_eq!(outcome.changed, 0);
        assert_eq!(
            outcome.script,
            "'resetprop' --delete 'sys.oem_unlock_allowed'\n"
        );
    }

    #[test]
    fn deleting_an_absent_property_emits_nothing() {
        let props = FakeProperties::new(&[]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("sys.oem_unlock_allowed\n", &props, &shell);
        assert_eq!(outcome.removed, 0);
        assert!(outcome.script.is_empty());
    }

    #[test]
    fn a_dotless_removal_target_is_rejected() {
        let props = FakeProperties::new(&[]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("adb\n", &props, &shell);
        assert_eq!(outcome.removed, 0);
        assert_eq!(
            notes_of(&outcome, crate::report::Level::Warn),
            vec!["hide_props: 'adb' has no value and is not a property name; ignoring".to_owned()]
        );
    }

    #[test]
    fn values_are_single_quoted_and_embedded_quotes_escaped() {
        let props = FakeProperties::new(&[("ro.build.tags", "old")]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("ro.build.tags=it's\n", &props, &shell);
        assert_eq!(
            outcome.script,
            "'resetprop' -n 'ro.build.tags' 'it'\\''s'\n"
        );
    }

    #[test]
    fn adb_off_disables_the_global_setting() {
        let props = FakeProperties::new(&[]);
        let shell = FakeShell::with_resetprop("resetprop");
        for value in ["off", "OFF", "disable", "0"] {
            let script = apply(&format!("adb={value}\n"), &props, &shell).script;
            // Detached: the boot script must not wait on the settings provider, and the redirect
            // must close the inherited stdout pipe so the runner's reader still sees EOF at once.
            assert!(script.starts_with("(\n"), "value {value}");
            assert!(script.ends_with(") >/dev/null 2>&1 &\n"), "value {value}");
            // It keeps putting until a read-back confirms the write landed...
            assert!(
                script.contains("/system/bin/settings put global adb_enabled 0"),
                "value {value}"
            );
            assert!(
                script.contains("/system/bin/settings get global adb_enabled"),
                "value {value}"
            );
            // ...and announces a timeout through the log binary instead of failing silently.
            assert!(
                script.contains("hide_props: adb=off unconfirmed after 30s"),
                "value {value}"
            );
        }
    }

    #[test]
    fn an_unsupported_adb_value_only_warns() {
        let props = FakeProperties::new(&[]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("adb=on\n", &props, &shell);
        assert!(outcome.script.is_empty());
        assert_eq!(
            notes_of(&outcome, crate::report::Level::Warn),
            vec!["hide_props: unsupported adb value 'on' (expected 'off')".to_owned()]
        );
    }

    #[test]
    fn usb_only_rewrites_properties_this_build_defines() {
        let props = FakeProperties::new(&[
            ("sys.usb.config", "ptp,adb"),
            ("persist.sys.usb.config", "ptp,adb"),
        ]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("usb=mtp\n", &props, &shell);
        // USB writes are not counted as `changed`, exactly like the Kotlin counter.
        assert_eq!(outcome.changed, 0);
        assert_eq!(
            outcome.script,
            "'resetprop' -n 'sys.usb.config' 'mtp'\n'resetprop' -n 'persist.sys.usb.config' 'mtp'\n"
        );
        assert_eq!(
            notes_of(&outcome, crate::report::Level::Debug),
            vec!["skipping 'sys.usb.state': not defined on this device".to_owned()]
        );
    }

    #[test]
    fn an_empty_usb_value_is_ignored() {
        let props = FakeProperties::new(&[("sys.usb.config", "adb")]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("usb=\n", &props, &shell);
        assert!(outcome.script.is_empty());
        assert!(
            outcome.notes.is_empty() || notes_of(&outcome, crate::report::Level::Warn).is_empty()
        );
    }

    #[test]
    fn an_unknown_dotted_switch_only_warns() {
        let props = FakeProperties::new(&[]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("selinux=off\n", &props, &shell);
        assert_eq!(
            notes_of(&outcome, crate::report::Level::Warn),
            vec!["ignoring unknown hide_props key: 'selinux'".to_owned()]
        );
        assert_eq!(outcome.changed, 0);
    }

    #[test]
    fn a_malformed_line_is_reported_with_its_text() {
        let props = FakeProperties::new(&[]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("=1\n", &props, &shell);
        assert_eq!(
            notes_of(&outcome, crate::report::Level::Warn),
            vec!["ignoring malformed hide_props line: =1".to_owned()]
        );
    }

    #[test]
    fn comments_and_blank_lines_are_dropped() {
        let props = FakeProperties::new(&[("ro.debuggable", "1")]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply(
            "# a comment\n\n   \nro.debuggable=0 # trailing\n",
            &props,
            &shell,
        );
        assert_eq!(outcome.changed, 1);
        assert_eq!(outcome.script, "'resetprop' -n 'ro.debuggable' '0'\n");
    }

    #[test]
    fn the_fingerprint_chain_is_composed_from_the_pending_identity() {
        let props = FakeProperties::new(&[
            ("ro.build.version.release", "14"),
            ("ro.build.id", "AP1A"),
            ("ro.build.version.incremental", "1"),
            ("ro.build.type", "user"),
            ("ro.build.tags", "release-keys"),
            ("ro.product.brand", "Old"),
            ("ro.product.name", "old_product"),
            ("ro.product.device", "old_device"),
            (
                "ro.build.fingerprint",
                "Old/old_product/old_device:14/AP1A/1:user/release-keys",
            ),
        ]);
        let shell = FakeShell::with_resetprop("resetprop");
        let config = "ro.product.brand=New\n\
                      ro.product.name=new_product\n\
                      ro.product.device=new_device\n\
                      fp=on\n";
        let outcome = apply(config, &props, &shell);
        // Three product identity writes plus the one fingerprint rewrite.
        assert_eq!(outcome.changed, 4);
        assert!(
            outcome.script.contains(
                "'resetprop' -n 'ro.build.fingerprint' \
                 'New/new_product/new_device:14/AP1A/1:user/release-keys'"
            ),
            "{}",
            outcome.script
        );
        // Only the system fingerprint is defined on this build, so no other partition is touched.
        assert_eq!(
            outcome.script.matches("'ro.build.fingerprint' -n").count(),
            0
        );
        assert_eq!(outcome.script.matches("build.fingerprint").count(), 1);
    }

    #[test]
    fn the_fingerprint_chain_is_skipped_when_the_build_identity_is_incomplete() {
        let props = FakeProperties::new(&[
            ("ro.build.version.release", "14"),
            ("ro.product.brand", "New"),
            ("ro.product.name", "new_product"),
            ("ro.product.device", "new_device"),
            (
                "ro.build.fingerprint",
                "Old/old_product/old_device:14/AP1A/1:user/release-keys",
            ),
        ]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("ro.product.brand=New\nfp=on\n", &props, &shell);
        assert_eq!(outcome.changed, 0);
        assert_eq!(
            notes_of(&outcome, crate::report::Level::Warn),
            vec![
                "skipping fingerprint chain: the build identity properties are incomplete"
                    .to_owned()
            ]
        );
    }

    #[test]
    fn the_fp_switch_accepts_every_documented_spelling() {
        // A complete build identity, so a well-formed `fp` value produces no warning at all: the
        // point of the test is the switch spelling, not the fingerprint chain.
        let props = FakeProperties::new(&[
            ("ro.build.version.release", "14"),
            ("ro.build.id", "AP1A"),
            ("ro.build.version.incremental", "1"),
            ("ro.build.type", "user"),
            ("ro.build.tags", "release-keys"),
            ("ro.product.brand", "google"),
            ("ro.product.name", "raven"),
            ("ro.product.device", "raven"),
            (
                "ro.build.fingerprint",
                "google/raven/raven:14/AP1A/1:user/release-keys",
            ),
        ]);
        let shell = FakeShell::with_resetprop("resetprop");
        for value in ["on", "ON", "true", "1", "yes", "enable", "enabled"] {
            let outcome = apply(&format!("fp={value}\n"), &props, &shell);
            assert!(
                notes_of(&outcome, crate::report::Level::Warn).is_empty(),
                "value {value} should be accepted"
            );
        }
        for value in ["off", "OFF", "false", "0", "no", "disable", "disabled"] {
            let outcome = apply(&format!("fp={value}\n"), &props, &shell);
            assert!(
                notes_of(&outcome, crate::report::Level::Warn).is_empty(),
                "value {value} should be accepted"
            );
        }
        let outcome = apply("fp=maybe\n", &props, &shell);
        assert_eq!(
            notes_of(&outcome, crate::report::Level::Warn),
            vec!["hide_props: unsupported fp value 'maybe' (expected 'on' or 'off')".to_owned()]
        );
    }

    #[test]
    fn resetprop_is_probed_once_no_matter_how_many_keys_follow() {
        let props = FakeProperties::new(&[("ro.a", "1"), ("ro.b", "2")]);
        let shell = FakeShell::with_resetprop("resetprop");
        let outcome = apply("ro.a=0\nro.b=0\nadb=off\n", &props, &shell);
        assert_eq!(outcome.changed, 2);
        assert_eq!(shell.scripts().len(), 2, "one probe plus one plan");
    }

    #[test]
    fn the_probe_walks_the_candidates_in_order() {
        let props = FakeProperties::new(&[]);
        let shell = FakeShell::with_resetprop("/data/adb/ksu/bin/resetprop");
        let _ = apply("ro.a=1\n", &props, &shell);
        let probe = shell.scripts().remove(0);
        let magisk = probe
            .find("/data/adb/magisk/resetprop")
            .unwrap_or(usize::MAX);
        let ksu = probe
            .find("/data/adb/ksu/bin/resetprop")
            .unwrap_or(usize::MAX);
        assert!(magisk < ksu, "{probe}");
        assert!(probe.ends_with("exit 1"), "{probe}");
    }

    #[test]
    fn set_property_short_circuits_when_the_value_matches() {
        let props = FakeProperties::new(&[("ro.boot.vbmeta.digest", "ab")]);
        let shell = FakeShell::with_resetprop("resetprop");
        assert!(set_property("ro.boot.vbmeta.digest", "ab", &props, &shell));
        assert!(shell.scripts().is_empty());
    }

    #[test]
    fn set_property_refuses_without_resetprop() {
        let props = FakeProperties::new(&[("ro.boot.vbmeta.digest", "ab")]);
        let shell = FakeShell::without_resetprop();
        assert!(!set_property("ro.boot.vbmeta.digest", "cd", &props, &shell));
        assert!(!shell.plan().contains("-n"));
    }

    #[test]
    fn set_property_reports_the_shell_status() {
        let props = FakeProperties::new(&[]);
        let failing = FakeShell {
            ok: false,
            ..FakeShell::with_resetprop("resetprop")
        };
        assert!(!set_property(
            "ro.boot.vbmeta.digest",
            "ab",
            &props,
            &failing
        ));
        let working = FakeShell::with_resetprop("resetprop");
        assert!(set_property(
            "ro.boot.vbmeta.digest",
            "ab",
            &props,
            &working
        ));
        assert_eq!(
            working.plan(),
            "'resetprop' -n 'ro.boot.vbmeta.digest' 'ab'\n"
        );
    }
}
