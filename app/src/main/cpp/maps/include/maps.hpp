// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once
#include <sys/types.h>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Forward declared so this header stays free of the FFI surface; `native_rust.h` declares the
// very same opaque struct.
struct TsMapList;

namespace ts {

struct MapInfo {
    uintptr_t start = 0;
    uintptr_t end = 0;
    uint8_t perms = 0;
    bool is_private = false;
    uintptr_t offset = 0;
    dev_t dev = 0;
    ino_t inode = 0;
    std::string path;
};

// One /proc/<pid>/maps snapshot. The parsed rows are what the injector walks, but the Rust list
// they were copied out of is kept alive as well: the module lookups run against that list
// (ts_maps_find_module), so releasing it at the end of the scan would force a second parse.
class MapScan {
public:
    // "self" reads our own mappings, which is what the injector wants for the local side. There
    // is deliberately no separate default constructor: it would silently produce an empty
    // snapshot instead of reading /proc.
    explicit MapScan(std::string_view pid = "self");
    ~MapScan();

    MapScan(const MapScan &) = delete;
    MapScan &operator=(const MapScan &) = delete;
    MapScan(MapScan &&other) noexcept;
    MapScan &operator=(MapScan &&other) noexcept;

    const std::vector<MapInfo> &entries() const {
        return entries_;
    }
    // Call sites that only want to walk the rows keep taking a plain vector reference.
    operator const std::vector<MapInfo> &() const {
        return entries_;
    }
    const TsMapList *list() const {
        return list_;
    }

private:
    void Release();

    TsMapList *list_ = nullptr;
    std::vector<MapInfo> entries_;
};

} // namespace ts
