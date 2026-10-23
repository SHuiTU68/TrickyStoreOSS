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

/// How one call's arguments split across the register and stack halves of an ABI.
///
/// Every Android ABI this payload targets passes a fixed number of leading arguments in
/// registers and pushes the rest onto the stack, so the split point and the number of bytes to
/// reserve follow from the argument count alone. Both are computed here instead of in each of the
/// four `remote_pre_call` branches, which is what kept them from drifting apart.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackArgsLayout {
    /// Leading arguments that the ABI passes in registers, i.e. `argc.min(register_args)`.
    pub register_args: usize,
    /// Trailing arguments that have to be pushed on the stack.
    pub stack_args: usize,
    /// Bytes those trailing arguments occupy, `stack_args * word_size`.
    pub stack_args_size: usize,
    /// Index of the first stack argument inside the argument vector, equal to `register_args`.
    pub first_stack_index: usize,
}

/// Splits `argc` arguments into the register and stack halves of an ABI.
///
/// `register_args` is the number of argument registers the ABI has (0 for i386 and ARM32, where
/// every argument goes on the stack, 6 for x86-64, 8 for AArch64) and `word_size` is the width of
/// one stack slot. When the ABI has more registers than the call has arguments the stack half is
/// empty and `first_stack_index` points one past the last argument, which is what the callers
/// want: they skip the stack write entirely on a zero size.
///
/// The multiplication wraps like the unsigned arithmetic it replaces; an argument list large
/// enough to overflow it cannot be built by this payload in the first place.
pub fn stack_args_layout(argc: usize, register_args: usize, word_size: usize) -> StackArgsLayout {
    let in_registers = argc.min(register_args);
    let on_stack = argc - in_registers;
    StackArgsLayout {
        register_args: in_registers,
        stack_args: on_stack,
        stack_args_size: on_stack.wrapping_mul(word_size),
        first_stack_index: in_registers,
    }
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

    /// The register counts the C++ side compiles in, mirrored here so the tests use the real ABI
    /// numbers instead of invented ones.
    const X86_64_REGISTER_ARGS: usize = 6;
    const AARCH64_REGISTER_ARGS: usize = 8;
    const ARM32_REGISTER_ARGS: usize = 4;
    const I386_REGISTER_ARGS: usize = 0;

    #[test]
    fn calls_that_fit_in_registers_need_no_stack() {
        let layout = stack_args_layout(3, X86_64_REGISTER_ARGS, 8);
        assert_eq!(layout.register_args, 3);
        assert_eq!(layout.stack_args, 0);
        assert_eq!(layout.stack_args_size, 0);
        assert_eq!(layout.first_stack_index, 3);
    }

    #[test]
    fn a_full_register_list_still_leaves_the_stack_half_empty() {
        let layout = stack_args_layout(AARCH64_REGISTER_ARGS, AARCH64_REGISTER_ARGS, 8);
        assert_eq!(layout.register_args, AARCH64_REGISTER_ARGS);
        assert_eq!(layout.stack_args, 0);
        assert_eq!(layout.stack_args_size, 0);
        assert_eq!(layout.first_stack_index, AARCH64_REGISTER_ARGS);
    }

    #[test]
    fn x86_64_pushes_everything_past_the_sixth_argument() {
        let layout = stack_args_layout(9, X86_64_REGISTER_ARGS, 8);
        assert_eq!(layout.register_args, 6);
        assert_eq!(layout.stack_args, 3);
        assert_eq!(layout.stack_args_size, 24);
        assert_eq!(layout.first_stack_index, 6);
    }

    #[test]
    fn aarch64_pushes_everything_past_the_eighth_argument() {
        let layout = stack_args_layout(10, AARCH64_REGISTER_ARGS, 8);
        assert_eq!(layout.register_args, 8);
        assert_eq!(layout.stack_args, 2);
        assert_eq!(layout.stack_args_size, 16);
        assert_eq!(layout.first_stack_index, 8);
    }

    #[test]
    fn arm32_uses_four_registers_and_four_byte_slots() {
        let layout = stack_args_layout(6, ARM32_REGISTER_ARGS, 4);
        assert_eq!(layout.register_args, 4);
        assert_eq!(layout.stack_args, 2);
        assert_eq!(layout.stack_args_size, 8);
        assert_eq!(layout.first_stack_index, 4);
    }

    #[test]
    fn i386_puts_the_whole_argument_list_on_the_stack() {
        let layout = stack_args_layout(3, I386_REGISTER_ARGS, 4);
        assert_eq!(layout.register_args, 0);
        assert_eq!(layout.stack_args, 3);
        assert_eq!(layout.stack_args_size, 12);
        assert_eq!(layout.first_stack_index, 0);
    }

    #[test]
    fn an_empty_argument_list_has_no_stack_half() {
        let layout = stack_args_layout(0, X86_64_REGISTER_ARGS, 8);
        let expected = StackArgsLayout {
            register_args: 0,
            stack_args: 0,
            stack_args_size: 0,
            first_stack_index: 0,
        };
        assert_eq!(layout, expected);
    }

    #[test]
    fn the_stack_size_wraps_like_the_cpp_multiply() {
        // Reaching this needs an argument count no ABI can express, but the arithmetic must not
        // trap in debug builds where it would abort the tracee.
        assert_eq!(stack_args_layout(2, 0, usize::MAX).stack_args_size, usize::MAX - 1);
    }

    #[test]
    fn reserving_past_the_stack_pointer_wraps() {
        assert_eq!(reserve_stack(0x10, 0x20), usize::MAX & !STACK_ALIGNMENT_MASK);
    }
}
