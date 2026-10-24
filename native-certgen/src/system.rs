//! Android implementations of the traits `hide_props` plans against.
//!
//! The planner is pure logic so it can be unit tested on the host; this module is the thin layer
//! that actually talks to the device: bionic's property area for reads, and `/system/bin/sh -c` for
//! the script the planner produces.

use std::process::{Command, Stdio};

use crate::hide_props::{PropertySource, ShellRunner, INTERPRETER};

/// Reads system properties straight out of bionic.
///
/// `__system_property_get` is the same call `android.os.SystemProperties.get` makes, so the planner
/// sees exactly what the Kotlin original saw: 0 bytes returned means "this build never defined the
/// property", which is the distinction every skip rule in `hide_props` depends on.
pub struct SystemProperties;

#[cfg(target_os = "android")]
mod bionic {
    use std::os::raw::{c_char, c_int};

    /// `PROP_VALUE_MAX` from bionic: the buffer size `__system_property_get` writes, NUL included.
    const PROP_VALUE_MAX: usize = 92;

    extern "C" {
        /// Copies the property's value into `value` and returns its length, or 0 when undefined.
        #[link_name = "__system_property_get"]
        fn system_property_get(name: *const c_char, value: *mut c_char) -> c_int;
    }

    pub fn get(name: &str) -> Option<String> {
        if name.is_empty() || name.contains('\0') {
            return None;
        }
        let mut name_bytes = Vec::with_capacity(name.len() + 1);
        name_bytes.extend_from_slice(name.as_bytes());
        name_bytes.push(0);
        let mut value = [0 as c_char; PROP_VALUE_MAX];
        // SAFETY: `name_bytes` is NUL-terminated and outlives the call; `value` is a stack buffer of
        // exactly `PROP_VALUE_MAX` bytes, which is the documented size bionic writes into. The
        // returned length is clamped to that buffer before it is used as a slice bound, so a
        // misbehaving implementation cannot make us read past it.
        let len = unsafe { system_property_get(name_bytes.as_ptr().cast(), value.as_mut_ptr()) };
        if len <= 0 || len as usize > PROP_VALUE_MAX {
            return None;
        }
        let bytes: Vec<u8> = value[..len as usize]
            .iter()
            .map(|byte| *byte as u8)
            .collect();
        String::from_utf8(bytes).ok()
    }
}

#[cfg(target_os = "android")]
impl PropertySource for SystemProperties {
    fn get(&self, name: &str) -> Option<String> {
        bionic::get(name)
    }
}

/// Host build: nothing here runs on a device, so environment variables stand in for the property
/// area. This keeps `cargo test` linkable without bionic.
#[cfg(not(target_os = "android"))]
impl PropertySource for SystemProperties {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Runs a script through `/system/bin/sh -c`.
///
/// stdout and stderr are merged, matching the Kotlin `ProcessBuilder(...).redirectErrorStream(true)`:
/// the one script whose output is parsed (`resetprop` location) only prints on stdout, and the
/// diagnostics from a failing command belong in the same log line as the success output. A non-zero
/// exit yields `None`, exactly like the Kotlin `runShell` returning null.
pub struct ShShell;

impl ShellRunner for ShShell {
    fn run(&self, script: &str) -> Option<String> {
        let output = Command::new(INTERPRETER)
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .output()
            .ok()?;
        let mut merged = String::from_utf8_lossy(&output.stdout).into_owned();
        merged.push_str(&String::from_utf8_lossy(&output.stderr));
        if output.status.success() {
            Some(merged)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_property_source_reads_the_environment() {
        // Only meaningful off-device, where the shim is compiled in.
        if cfg!(target_os = "android") {
            return;
        }
        std::env::set_var("CERTGEN_TEST_PROPERTY", "value");
        assert_eq!(
            SystemProperties.get("CERTGEN_TEST_PROPERTY"),
            Some("value".to_owned())
        );
        std::env::remove_var("CERTGEN_TEST_PROPERTY");
        assert_eq!(SystemProperties.get("CERTGEN_TEST_PROPERTY"), None);
    }

    #[test]
    fn the_shell_runner_merges_output_and_reports_the_exit_status() {
        // `/system/bin/sh` does not exist on the host, so this only asserts the failure path there.
        let merged = ShShell.run("printf 'out'; printf 'err' >&2");
        if cfg!(target_os = "android") {
            assert_eq!(merged.as_deref(), Some("outerr"));
        }
        assert_eq!(ShShell.run("exit 3"), None);
    }
}
