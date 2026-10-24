//! Human-readable rendering of a `waitpid` status.
//!
//! This replaces `parse_status()` and the `parse_ptrace_event()` macro table in `inject/utils.hpp`.
//! The C++ version formatted into a fixed 128-byte buffer with `snprintf`; here the string is built
//! into a `String` and the caller only ever sees it truncated to its own buffer, so a long event
//! name can no longer be silently cut in half mid-word by an internal limit.

/// Names of signals 1..=31, in the order bionic's `sys_signame` uses.
const SIGNAL_NAMES: [&str; 31] = [
    "SIGHUP",    // 1
    "SIGINT",    // 2
    "SIGQUIT",   // 3
    "SIGILL",    // 4
    "SIGTRAP",   // 5
    "SIGABRT",   // 6
    "SIGBUS",    // 7
    "SIGFPE",    // 8
    "SIGKILL",   // 9
    "SIGUSR1",   // 10
    "SIGSEGV",   // 11
    "SIGUSR2",   // 12
    "SIGPIPE",   // 13
    "SIGALRM",   // 14
    "SIGTERM",   // 15
    "SIGSTKFLT", // 16
    "SIGCHLD",   // 17
    "SIGCONT",   // 18
    "SIGSTOP",   // 19
    "SIGTSTP",   // 20
    "SIGTTIN",   // 21
    "SIGTTOU",   // 22
    "SIGURG",    // 23
    "SIGXCPU",   // 24
    "SIGXFSZ",   // 25
    "SIGVTALRM", // 26
    "SIGPROF",   // 27
    "SIGWINCH",  // 28
    "SIGIO",     // 29
    "SIGPWR",    // 30
    "SIGSYS",    // 31
];

/// The real-time signal range, as the kernel numbers it on the architectures this ships for.
const SIGRTMIN: i32 = 32;
const SIGRTMAX: i32 = 64;

/// The name of `signal`, matching what `sigabbrev_np` reports for the same signal.
pub fn signal_name(signal: i32) -> String {
    if (1..=31).contains(&signal) {
        // Index is bounded by the range check above.
        return SIGNAL_NAMES[(signal - 1) as usize].to_string();
    }
    if (SIGRTMIN..=SIGRTMAX).contains(&signal) {
        return match signal - SIGRTMIN {
            0 => "SIGRTMIN".to_string(),
            offset => format!("SIGRTMIN+{offset}"),
        };
    }
    "(unknown)".to_string()
}

/// The name of the ptrace event carried in a stopped status, matching `parse_ptrace_event()`.
pub fn ptrace_event(status: i32) -> &'static str {
    match status >> 16 {
        1 => "PTRACE_EVENT_FORK",
        2 => "PTRACE_EVENT_VFORK",
        3 => "PTRACE_EVENT_CLONE",
        4 => "PTRACE_EVENT_EXEC",
        5 => "PTRACE_EVENT_VFORK_DONE",
        6 => "PTRACE_EVENT_EXIT",
        7 => "PTRACE_EVENT_SECCOMP",
        128 => "PTRACE_EVENT_STOP",
        _ => "(no event)",
    }
}

/// Renders a `waitpid` status the way `parse_status()` used to.
pub fn describe(status: i32) -> String {
    let hex = status as u32;
    if status & 0x7f == 0 {
        // WIFEXITED
        return format!("0x{hex:x} exited with code {}", (status >> 8) & 0xff);
    }
    if (status & 0x7f) != 0x7f {
        // WIFSIGNALED: a non-zero, non-stop low byte means the child died from a signal.
        let signal = status & 0x7f;
        return format!(
            "0x{hex:x} terminated by signal {}({signal})",
            signal_name(signal)
        );
    }
    // WIFSTOPPED() checks the low byte, not the low seven bits, because `0x7f` in the low
    // seven bits means "stopped" and the eighth bit carries the core-dump flag.
    if (status & 0xff) == 0x7f {
        let signal = (status >> 8) & 0xff;
        return format!(
            "0x{hex:x} stopped by signal={}({signal}), event={}",
            signal_name(signal),
            ptrace_event(status)
        );
    }
    format!("0x{hex:x} unknown status")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_normal_exit() {
        // exit code 3
        assert_eq!(describe(3 << 8), "0x300 exited with code 3");
    }

    #[test]
    fn renders_a_signal_death() {
        // killed by SIGKILL
        assert_eq!(describe(9), "0x9 terminated by signal SIGKILL(9)");
        assert_eq!(describe(11), "0xb terminated by signal SIGSEGV(11)");
    }

    #[test]
    fn renders_a_stop_with_its_ptrace_event() {
        // stopped by SIGTRAP, PTRACE_EVENT_EXEC
        let status = (4 << 16) | (5 << 8) | 0x7f;
        assert_eq!(
            describe(status),
            "0x4057f stopped by signal=SIGTRAP(5), event=PTRACE_EVENT_EXEC"
        );
    }

    #[test]
    fn names_the_signals_it_has_to_name() {
        assert_eq!(signal_name(0), "(unknown)");
        assert_eq!(signal_name(1), "SIGHUP");
        assert_eq!(signal_name(31), "SIGSYS");
        assert_eq!(signal_name(32), "SIGRTMIN");
        assert_eq!(signal_name(33), "SIGRTMIN+1");
        assert_eq!(signal_name(64), "SIGRTMIN+32");
        assert_eq!(signal_name(65), "(unknown)");
        assert_eq!(signal_name(-1), "(unknown)");
    }

    #[test]
    fn maps_the_ptrace_events() {
        assert_eq!(ptrace_event(0), "(no event)");
        assert_eq!(ptrace_event(7 << 16), "PTRACE_EVENT_SECCOMP");
        assert_eq!(ptrace_event(128 << 16), "PTRACE_EVENT_STOP");
    }

    #[test]
    fn an_empty_event_still_reads_as_a_stop() {
        let status = (19 << 8) | 0x7f;
        assert_eq!(
            describe(status),
            "0x137f stopped by signal=SIGSTOP(19), event=(no event)"
        );
    }

    #[test]
    fn falls_back_for_a_status_no_macro_recognises() {
        // The low seven bits say "stopped", but WIFSTOPPED() compares the whole low byte
        // with 0x7f, so 0xff is neither an exit, a signal death nor a stop.
        assert_eq!(describe(0xff), "0xff unknown status");
    }
}
