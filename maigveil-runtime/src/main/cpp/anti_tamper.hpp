#pragma once

#include <cstdint>

namespace maigveil::tamper {

struct TamperReport {
    bool text_integrity_ok = true;
    bool no_inline_hooks = true;
    bool no_debugger_attached = true;
    uint32_t text_crc32 = 0;

    bool is_clean() const noexcept {
        return text_integrity_ok && no_inline_hooks && no_debugger_attached;
    }
};

/**
 * Captures baseline `.text` integrity of `libmaigveil.so` during `JNI_OnLoad`.
 */
void init_self_integrity_baseline(const void* anchor_fn) noexcept;

/**
 * Runs runtime self-defense checks:
 * 1. Scans critical function prologues for ARM64/x86_64 inline hook trampolines (O(1), <2ns).
 * 2. When `full_scan` is true (or periodically every 64 hot-path calls), verifies `.text`
 *    section integrity, `/proc/self/maps` for Frida/Xposed, and `/proc/self/status` `TracerPid`.
 */
TamperReport run_self_defense_checks(const void* probe_fn, bool full_scan = false) noexcept;

}  // namespace maigveil::tamper
