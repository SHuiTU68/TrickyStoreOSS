// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#include "maps.hpp"

#include <string>
#include <utility>

#include "native_rust.h"

namespace ts {
namespace {
// Copies one list entry into the C++-friendly row. `path_len` is authoritative, the terminator is
// only there for convenience.
MapInfo ToInfo(const TsMapEntry &entry) {
    MapInfo info;
    info.start = entry.start;
    info.end = entry.end;
    info.perms = entry.perms;
    info.is_private = entry.is_private != 0;
    info.offset = entry.offset;
    info.dev = static_cast<dev_t>(entry.dev);
    info.inode = static_cast<ino_t>(entry.inode);
    info.path.assign(entry.path, entry.path_len);
    return info;
}
} // namespace

// The parsing now lives in Rust (native-inject/src/maps.rs, reached through ts_maps_scan); this
// wrapper only keeps the C++-friendly `MapInfo` shape so the injector's call sites stay
// untouched. Unlike the old `MapInfo::Scan` the list is owned by the snapshot instead of being
// freed on the spot, because the module lookups read it directly.
MapScan::MapScan(std::string_view pid) {
    // `pid` is a view and carries no terminator, so the parser gets a copy it can treat as a C
    // string.
    const std::string pid_str{pid};
    list_ = ts_maps_scan(pid_str.c_str());
    if (list_ == nullptr) return;
    const size_t count = ts_maps_len(list_);
    entries_.reserve(count);
    for (size_t i = 0; i < count; i++) {
        const TsMapEntry *entry = ts_maps_entry(list_, i);
        if (entry == nullptr) continue;
        // The path is copied while the list is still alive.
        entries_.push_back(ToInfo(*entry));
    }
    entries_.shrink_to_fit();
}

MapScan::~MapScan() {
    Release();
}

MapScan::MapScan(MapScan &&other) noexcept : list_(other.list_), entries_(std::move(other.entries_)) {
    other.list_ = nullptr;
}

MapScan &MapScan::operator=(MapScan &&other) noexcept {
    if (this != &other) {
        Release();
        list_ = other.list_;
        entries_ = std::move(other.entries_);
        other.list_ = nullptr;
    }
    return *this;
}

void MapScan::Release() {
    ts_maps_free(list_);
    list_ = nullptr;
}
} // namespace ts
