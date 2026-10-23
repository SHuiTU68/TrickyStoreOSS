// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#include "maps.hpp"

#include <string>

#include "native_rust.h"

namespace ts {
// The parsing now lives in Rust (native-inject/src/maps.rs, reached through ts_maps_scan); this
// wrapper only keeps the C++-friendly `MapInfo` shape so the injector's call sites stay
// untouched.
std::vector<MapInfo> MapInfo::Scan(std::string_view pid) {
    std::vector<MapInfo> infos;
    // `pid` is a view and carries no terminator, so the parser gets a copy it can treat as a C
    // string.
    const std::string pid_str{pid};
    TsMapList *list = ts_maps_scan(pid_str.c_str());
    if (list == nullptr) return infos;
    const size_t count = ts_maps_len(list);
    infos.reserve(count);
    for (size_t i = 0; i < count; i++) {
        const TsMapEntry *entry = ts_maps_entry(list, i);
        if (entry == nullptr) continue;
        auto &info = infos.emplace_back();
        info.start = entry->start;
        info.end = entry->end;
        info.perms = entry->perms;
        info.is_private = entry->is_private != 0;
        info.offset = entry->offset;
        info.dev = static_cast<dev_t>(entry->dev);
        info.inode = static_cast<ino_t>(entry->inode);
        // The path is copied while the list is still alive; `path_len` is authoritative, the
        // terminator is only there for convenience.
        info.path.assign(entry->path, entry->path_len);
    }
    ts_maps_free(list);
    infos.shrink_to_fit();
    return infos;
}
} // namespace ts
