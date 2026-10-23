//! Stop-site decisions for the remote function-call trampoline.
//!
//! `remote_post_call` in `app/src/main/cpp/inject/utils.cpp` drives one remote call by
//! continuing the tracee and inspecting every `waitpid` stop it produces. The *policy*
//! (which stop means "the call returned", which means "we crashed", which is a benign
//! signal to swallow) lives here; the `ptrace`/`waitpid` syscalls themselves stay in C++.
//!
//! The caller always feeds in the raw register snapshot it just read, so this module is
//! pure and unit-testable without a tracee.

/// `SIGSEGV` as seen by Bionic. Identical on every Android ABI this payload targets.
pub const SIGSEGV: i32 = 11;

/// `SIGCHLD` as seen by Bionic. Identical on every Android ABI this payload targets.
pub const SIGCHLD: i32 = 17;

/// What the trampoline should do after a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallStep {
    /// The tracee stopped at the value planted on the stack/link register: the call is done
    /// and the return value is already in the return register.
    Completed,
    /// `SIGSEGV` somewhere other than the planted return address: the remote function blew
    /// up and the tracee is sitting on a faulting instruction.
    Crashed,
    /// A signal that is not ours to interpret (`SIGCHLD` from the tracee's own children).
    /// Resume the tracee with the signal suppressed.
    Suppress,
    /// Any other stop: the call cannot be completed safely.
    Unexpected,
}

impl CallStep {
    /// The stable integer encoding used across the C ABI.
    pub const fn code(self) -> i32 {
        match self {
            Self::Completed => 0,
            Self::Crashed => 1,
            Self::Suppress => 2,
            Self::Unexpected => 3,
        }
    }
}

/// Classifies a stop observed while a remote call is in flight.
///
/// `expected_return_addr` is the address planted as the return target; a `SIGSEGV` exactly
/// there is how the trampoline detects "the callee executed `ret`" on ABIs where that is
/// the only reliable marker, so it counts as success rather than a crash.
pub fn classify_stop(stop_signal: i32, reg_ip: u64, expected_return_addr: u64) -> CallStep {
    if stop_signal == SIGSEGV {
        if reg_ip == expected_return_addr {
            CallStep::Completed
        } else {
            CallStep::Crashed
        }
    } else if stop_signal == SIGCHLD {
        CallStep::Suppress
    } else {
        CallStep::Unexpected
    }
}

/// Mask that clears the low four bits, i.e. the 16-byte `sp` alignment every Android ABI wants.
pub const STACK_ALIGNMENT_MASK: usize = 0xf;

/// Reserves `bytes` bytes on the tracee stack and returns the 16-byte-aligned pointer.
///
/// This is the arithmetic step behind `align_stack`: subtract first, then round down, which is
/// exactly what the C++ helper did with two statements. The subtraction wraps instead of trapping
/// when `bytes` exceeds the current stack pointer, matching the unsigned arithmetic it replaces.
pub fn reserve_stack(sp: usize, bytes: usize) -> usize {
    sp.wrapping_sub(bytes) & !STACK_ALIGNMENT_MASK
}

#[cfg(test)]
mod tests {
    use super::*;

    const RETURN_ADDR: u64 = 0x7f00_1234_5000;

    #[test]
    fn fault_at_the_planted_return_address_completes_the_call() {
        assert_eq!(
            classify_stop(SIGSEGV, RETURN_ADDR, RETURN_ADDR),
            CallStep::Completed
        );
    }

    #[test]
    fn fault_elsewhere_is_a_crash() {
        assert_eq!(
            classify_stop(SIGSEGV, RETURN_ADDR + 4, RETURN_ADDR),
            CallStep::Crashed
        );
    }

    #[test]
    fn a_zero_expected_address_still_compares_exactly() {
        // `remote_post_call` is called with `expected_return_addr == 0` when the caller
        // resumes a process it did not trampoline itself; the original C++ compared the
        // values without special-casing zero, and so does this.
        assert_eq!(classify_stop(SIGSEGV, 0, 0), CallStep::Completed);
        assert_eq!(classify_stop(SIGSEGV, 4, 0), CallStep::Crashed);
    }

    #[test]
    fn sigchld_is_swallowed() {
        assert_eq!(classify_stop(SIGCHLD, 0, RETURN_ADDR), CallStep::Suppress);
    }

    #[test]
    fn everything_else_is_unexpected() {
        for signal in [0, 2, 5, 11 + 1, 19, 64] {
            assert_eq!(
                classify_stop(signal, RETURN_ADDR, RETURN_ADDR),
                CallStep::Unexpected,
                "signal {signal} should not be treated as a completion"
            );
        }
    }

    #[test]
    fn the_abi_codes_are_stable() {
        assert_eq!(CallStep::Completed.code(), 0);
        assert_eq!(CallStep::Crashed.code(), 1);
        assert_eq!(CallStep::Suppress.code(), 2);
        assert_eq!(CallStep::Unexpected.code(), 3);
    }
    #[test]
    fn reserving_aligns_the_stack_pointer() {
        assert_eq!(reserve_stack(0x1000, 0), 0x1000);
        assert_eq!(reserve_stack(0x1008, 0), 0x1000);
        assert_eq!(reserve_stack(0x1000, 8), 0xff0);
        assert_eq!(reserve_stack(0x1000, 0x20), 0xfe0);
    }

    #[test]
    fn reserving_rounds_down_whatever_the_start_pointer() {
        // The subtraction happens first, so an already unaligned pointer still lands on a
        // 16-byte boundary.
        assert_eq!(reserve_stack(0x1fff, 1), 0x1ff0);
    }

    #[test]
    fn reserving_past_the_stack_pointer_wraps() {
        assert_eq!(reserve_stack(0x10, 0x20), usize::MAX & !STACK_ALIGNMENT_MASK);
    }
}
