// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stddef.h>
#include <stdint.h>

// Declarations for the `#[no_mangle]` entry points of `native-inject/src/ffi.rs`.
//
// The Rust side is compiled to a static archive (`librustinject.a`) which is linked into
// libinject.so, so nothing here is resolved at runtime: these are ordinary symbols with a C
// calling convention, deliberately free of any C++ type so the layout cannot drift between the
// two compilers.
//
// `is_private` is a `uint8_t` rather than `bool` to keep the field width guaranteed instead of
// implementation-defined; the Rust side stores it as `u8` for the same reason.
struct TsMapEntry {
    uintptr_t start;
    uintptr_t end;
    uint8_t perms; // PROT_READ | PROT_WRITE | PROT_EXEC
    uint8_t is_private;
    uintptr_t offset;
    uint64_t dev;
    uint64_t inode;
    const char *path; // NUL-terminated, owned by the list
    size_t path_len;  // length without the terminator
};

// Opaque owner of the entry array and of the storage the `path` pointers point into.
struct TsMapList;

// Verdicts returned by ts_classify_stop(). Kept in sync with `CallStep::code()` in
// `native-inject/src/remote.rs`.
enum {
    TS_CALL_COMPLETED = 0,
    TS_CALL_CRASHED = 1,
    TS_CALL_SUPPRESS = 2,
    TS_CALL_UNEXPECTED = 3,
};

// Mapping selectors for ts_maps_find_module(). Kept in sync with `ModuleMatch` in
// `native-inject/src/maps.rs`.
enum {
    // The mapping at the module's file offset zero, i.e. the load bias.
    TS_MODULE_BASE = 0,
    // A mapping of the module without PROT_EXEC, i.e. a page that can host the return trampoline.
    TS_MODULE_NON_EXEC = 1,
};

extern "C" {
// Parses /proc/<pid>/maps; a null `pid` means the calling process. Returns null when the file
// cannot be read, and must be released with ts_maps_free().
struct TsMapList *ts_maps_scan(const char *pid);
size_t ts_maps_len(const struct TsMapList *list);
const struct TsMapEntry *ts_maps_entry(const struct TsMapList *list, size_t index);
void ts_maps_free(struct TsMapList *list);

// Start address of the first mapping selected by `mode` (a TS_MODULE_* value) whose path ends
// with the `suffix_len`-byte suffix, or 0 when nothing matches. The suffix needs no terminator.
uintptr_t ts_maps_find_module(const struct TsMapList *list, const char *suffix, size_t suffix_len, int mode);

// Maps a symbol address resolved in our own process onto the tracee's module base, keeping the
// distance it has from `local_base`. Both steps wrap, like the ptrdiff_t arithmetic it replaces.
uintptr_t ts_translate_remote_symbol(uintptr_t local_base, uintptr_t remote_base, uintptr_t symbol_addr);

// snprintf-style renderers: they return the length the text needs, excluding the terminator, so
// a return value >= capacity means the output was truncated. A null buffer or a zero capacity
// only reports the length.
size_t ts_describe_status(int status, char *out, size_t capacity);
size_t ts_generate_magic(size_t length, char *out, size_t capacity);

// setfilecon(3) and the sockcreate knob writer. Both return 0 on success and -1 with errno set,
// exactly like the wrapped syscalls.
int ts_setfilecon(const char *path, const char *context);
int ts_set_sockcreate_con(const char *context);

// The PTRACE_EVENT_* name for a stopped status; the pointer is static and never freed.
const char *ts_ptrace_event(int status);

// Decides what a stop means while a remote call is in flight, given the signal that stopped the
// tracee and the instruction pointer read right after. Returns one of the TS_CALL_* values above.
int ts_classify_stop(int stop_signal, uint64_t reg_ip, uint64_t expected_return_addr);
}
