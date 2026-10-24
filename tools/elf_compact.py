#!/usr/bin/env python3
"""Reclaims the file holes that `llvm-objcopy --remove-section` leaves behind.

Removing a section from a linked ELF does not shrink the file: objcopy keeps every
offset in place and zero-fills the bytes the section used to occupy, so a 191 KB
`.eh_frame` turns into a 191 KB run of zeros that still occupies its blocks on
disk. Only the compressed archive gets smaller, because zeros deflate to nothing.

The holes can be reclaimed safely in one specific case: when a hole sits at the
*tail* of a `PT_LOAD` segment, every following segment can simply move down in the
file, because a segment's file offset is independent of its virtual address as long
as `p_offset ≡ p_vaddr (mod p_align)` still holds. Nothing references the bytes in
between - no section header points into the hole, and the loader only ever reads
`[p_offset, p_offset + p_filesz)`.

A hole in the *middle* of a segment is left alone. Moving content inside a segment
would have to rewrite the addresses baked into code, which is a relink, not a
compaction.

Usage: elf_compact.py <file.so> [--check]

`--check` re-verifies an already compacted file without touching it.
"""

from __future__ import annotations

import os
import struct
import sys

EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
PHDR = struct.Struct("<IIQQQQQQ")
SHDR = struct.Struct("<IIQQQQIIQQ")

PT_NULL = 0
PT_LOAD = 1
PT_PHDR = 6
PT_GNU_EH_FRAME = 0x6474E550
SHT_NOBITS = 8
SHT_NULL = 0
ET_DYN = 3
EM_AARCH64 = 183

# How many holes a single pass loop is allowed to reclaim. Really a safety belt: a
# normal build has one (the stripped unwind tables), a second only shows up if a
# future tool inserts something else before the link.
MAX_PASSES = 8


class ElfError(Exception):
    pass


def parse(data: bytes) -> dict:
    if len(data) < EHDR.size:
        raise ElfError("file is smaller than an ELF64 header")
    magic, e_type, e_machine, _ver, _entry, e_phoff, e_shoff, _flags, _ehsize, e_phentsize, \
        e_phnum, e_shentsize, e_shnum, e_shstrndx = EHDR.unpack_from(data, 0)
    if magic[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    if magic[4] != 2 or magic[5] != 1:
        raise ElfError("only little-endian ELF64 is supported")
    if e_type != ET_DYN:
        raise ElfError(f"expected ET_DYN (3), got {e_type}")
    if e_machine != EM_AARCH64:
        raise ElfError(f"expected AArch64 (183), got {e_machine}")

    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
         p_align) = PHDR.unpack_from(data, off)
        phdrs.append({
            "index": i, "type": p_type, "flags": p_flags, "offset": p_offset,
            "vaddr": p_vaddr, "paddr": p_paddr, "filesz": p_filesz,
            "memsz": p_memsz, "align": p_align, "hdr_off": off,
        })

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
         sh_info, sh_addralign, sh_entsize) = SHDR.unpack_from(data, off)
        sections.append({
            "index": i, "type": sh_type, "addr": sh_addr, "offset": sh_offset,
            "size": sh_size, "hdr_off": off,
        })

    return {
        "header": {"ehsize": _ehsize, "phoff": e_phoff, "phentsize": e_phentsize,
                   "phnum": e_phnum, "shoff": e_shoff, "shentsize": e_shentsize},
        "phdrs": phdrs,
        "sections": sections,
    }


def header_span(elf: dict) -> int:
    """End of the region that holds the ELF header and the program header table.

    Those bytes are *expected* to change during compaction (that is where the new
    offsets are written), so segment image comparisons have to skip them.
    """
    head = elf["header"]
    return max(head["ehsize"], head["phoff"] + head["phentsize"] * head["phnum"])


def section_span(elf: dict, phdr: dict) -> int:
    """File offset one past the last section byte that lives in this segment."""
    end = phdr["offset"]
    for section in elf["sections"]:
        if section["type"] in (SHT_NULL, SHT_NOBITS) or section["size"] == 0:
            continue
        if section["offset"] < phdr["offset"] or section["offset"] >= phdr["offset"] + phdr["filesz"]:
            continue
        end = max(end, section["offset"] + section["size"])
    return end


def snapshot(data: bytes, elf: dict) -> dict:
    """Everything a rewrite must preserve: section bytes and segment file images."""
    return {
        "sections": [
            (s["index"], data[s["offset"]:s["offset"] + s["size"]])
            for s in elf["sections"]
            if s["type"] not in (SHT_NULL, SHT_NOBITS) and s["size"] > 0
        ],
        "segments": [
            (p["index"], data[p["offset"]:p["offset"] + p["filesz"]])
            for p in elf["phdrs"] if p["type"] == PT_LOAD
        ],
    }


def verify(before: dict, data: bytes, elf: dict) -> None:
    for index, old in before["sections"]:
        section = elf["sections"][index]
        new = data[section["offset"]:section["offset"] + section["size"]]
        if new != old:
            raise ElfError(f"section #{index} changed while compacting")
    head = min(header_span(elf), len(data))
    for index, old in before["segments"]:
        phdr = next(p for p in elf["phdrs"] if p["index"] == index)
        new = data[phdr["offset"]:phdr["offset"] + phdr["filesz"]]
        # A segment may only lose file bytes at its very end, and only zeros: those
        # are the bytes we just deleted, now provided by the loader's zero-fill.
        if len(new) > len(old):
            raise ElfError(f"segment #{index} grew while compacting")
        # The ELF header and the program header table are rewritten on purpose.
        skip = min(head, len(new)) if phdr["offset"] == 0 else 0
        if new[skip:] != old[skip:len(new)]:
            raise ElfError(f"segment #{index} changed while compacting")
        if old[len(new):].strip(b"\x00"):
            raise ElfError(f"segment #{index} lost non-zero bytes while compacting")
        if phdr["memsz"] < phdr["filesz"]:
            raise ElfError(f"segment #{index} has filesz > memsz after compacting")
    for phdr in elf["phdrs"]:
        align = phdr["align"]
        if phdr["type"] == PT_LOAD and align > 1 and phdr["offset"] % align != phdr["vaddr"] % align:
            raise ElfError(f"segment #{phdr['index']} is no longer congruent to its alignment")


def normalize_stale_headers(data: bytearray, elf: dict) -> list[str]:
    """Neutralises segment headers whose backing bytes were stripped away.

    `llvm-objcopy --remove-section=.eh_frame_hdr` deletes the section but leaves
    `PT_GNU_EH_FRAME` pointing at the zeroed range. Nothing crashes today, because
    the unwinder only walks it on an exception, but it is a dangling pointer into
    a hole. A real `.eh_frame_hdr` starts with version 1, so anything else is dead
    weight: turn the entry into `PT_NULL`, which the loader skips.
    """
    notes = []
    for phdr in elf["phdrs"]:
        if phdr["type"] != PT_GNU_EH_FRAME or phdr["filesz"] == 0:
            continue
        start = phdr["offset"]
        version = data[start] if start < len(data) else 0
        if version == 1:
            continue
        notes.append(f"PT_GNU_EH_FRAME at 0x{start:x} was dangling")
        phdr["type"] = PT_NULL
        phdr["offset"] = 0
        phdr["vaddr"] = 0
        phdr["paddr"] = 0
        phdr["filesz"] = 0
        phdr["memsz"] = 0
        phdr["align"] = 0
    return notes


def compact_once(data: bytearray, elf: dict) -> tuple[int, str] | None:
    """Finds one reclaimable tail hole, removes it in place, returns (bytes, description)."""
    loads = sorted((p for p in elf["phdrs"] if p["type"] == PT_LOAD), key=lambda p: p["offset"])
    for previous, current in zip(loads, loads[1:]):
        tail = section_span(elf, previous)
        gap = current["offset"] - tail
        align = current["align"] if current["align"] > 1 else 1
        if gap <= 0:
            continue
        # The shift has to keep `p_offset ≡ p_vaddr (mod p_align)`, and both are
        # congruent today, so the amount removed must itself be a multiple of it.
        removal = (gap // align) * align
        if removal <= 0:
            continue
        start = tail
        end = start + removal
        if end > current["offset"]:
            continue
        if any(s["type"] not in (SHT_NULL, SHT_NOBITS) and s["size"] > 0
               and s["offset"] < end and s["offset"] + s["size"] > start
               for s in elf["sections"]):
            continue
        # Only a pure hole is reclaimable; a stray non-zero byte means this range is
        # referenced by something we do not understand, so leave the file alone.
        if data[start:end].count(0) != removal:
            continue

        memsz_old = previous["memsz"]
        del data[start:end]
        previous["filesz"] = start - previous["offset"]
        # The virtual size must not move: the loader still reserves the same address
        # range, it just zero-fills what no longer has a file image. Anything that
        # used to be mapped from the hole was already zero, so the memory contents
        # are bit-for-bit the same.
        previous["memsz"] = memsz_old

        for phdr in elf["phdrs"]:
            if phdr is not previous and phdr["offset"] >= end:
                phdr["offset"] -= removal
            # The tables themselves move down too, so their in-file positions shift.
            if phdr["hdr_off"] >= end:
                phdr["hdr_off"] -= removal
        for section in elf["sections"]:
            if section["offset"] >= end:
                section["offset"] -= removal
            if section["hdr_off"] >= end:
                section["hdr_off"] -= removal
        if elf["header"]["shoff"] >= end:
            elf["header"]["shoff"] -= removal
        return removal, f"hole [0x{start:x}, 0x{end:x}) before segment #{current['index']}"
    return None


def write_back(data: bytearray, elf: dict) -> None:
    for phdr in elf["phdrs"]:
        PHDR.pack_into(data, phdr["hdr_off"], phdr["type"], phdr["flags"],
                       phdr["offset"], phdr["vaddr"], phdr["paddr"], phdr["filesz"],
                       phdr["memsz"], phdr["align"])
    for section in elf["sections"]:
        (sh_name, sh_type, sh_flags, sh_addr, _sh_offset, sh_size, sh_link, sh_info,
         sh_addralign, sh_entsize) = SHDR.unpack_from(data, section["hdr_off"])
        SHDR.pack_into(data, section["hdr_off"], sh_name, sh_type, sh_flags,
                       sh_addr, section["offset"], sh_size, sh_link, sh_info,
                       sh_addralign, sh_entsize)
    ehdr = list(EHDR.unpack_from(data, 0))
    ehdr[6] = elf["header"]["shoff"]
    EHDR.pack_into(data, 0, *ehdr)


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    flags = [a for a in argv[1:] if a.startswith("-")]
    unknown = [f for f in flags if f != "--check"]
    if not args or unknown:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: elf_compact.py [--check] <file.so> [more.so ...]", file=sys.stderr)
        return 2
    check_only = "--check" in flags
    status = 0
    for path in args:
        status = max(status, process_one(path, check_only))
    return status


def process_one(path: str, check_only: bool) -> int:
    if not os.path.isfile(path):
        print(f"compact: {path} missing", file=sys.stderr)
        return 2

    with open(path, "rb") as handle:
        data = bytearray(handle.read())
    elf = parse(data)
    original = len(data)
    before = snapshot(data, elf)
    notes = normalize_stale_headers(data, elf)

    if check_only:
        verify(before, data, elf)
        if notes:
            print(f"compact: {os.path.basename(path)} has {len(notes)} dangling segment header(s): "
                  f"{'; '.join(notes)}", file=sys.stderr)
            return 1
        print(f"compact: {os.path.basename(path)} verified ({original} bytes, structure intact)")
        return 0

    for _ in range(MAX_PASSES):
        result = compact_once(data, elf)
        if result is None:
            break
        notes.append(result[1])

    if not notes:
        print(f"compact: {os.path.basename(path)} already tight ({original} bytes)")
        return 0

    write_back(data, elf)
    reparsed = parse(data)
    verify(before, data, reparsed)

    with open(path, "wb") as handle:
        handle.write(data)
    print(
        f"compact: {os.path.basename(path)} {original} -> {len(data)} bytes "
        f"({original - len(data)} bytes of padding reclaimed: {'; '.join(notes)})"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except ElfError as error:
        print(f"compact: {error}", file=sys.stderr)
        sys.exit(1)
