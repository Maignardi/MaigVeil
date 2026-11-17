#pragma once

#include "syscalls.hpp"
#include <cstddef>
#include <cstdint>
#include <sys/mman.h>

namespace maigveil::mem {

/**
 * Compiler-barrier-hardened memory wipe to prevent dead-store elimination.
 */
__attribute__((noinline)) inline void secure_zero(void* ptr, size_t len) noexcept {
    if (!ptr || len == 0) return;
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
    asm volatile("" : : "r"(ptr) : "memory");
}

/**
 * Allocates page-aligned anonymous memory locked against swap (`mlock`)
 * for Zero-Trace secret exposure via `DirectByteBuffer`.
 */
struct LockedBuffer {
    void* ptr = nullptr;
    size_t size = 0;
    bool locked = false;

    static LockedBuffer allocate(size_t requested_bytes) noexcept {
        LockedBuffer buf{};
        if (requested_bytes == 0) return buf;
        void* p = sys::direct_mmap_anon(requested_bytes);
        if (p == MAP_FAILED || p == nullptr) {
            return buf;
        }
        buf.ptr = p;
        buf.size = requested_bytes;
        buf.locked = (sys::direct_mlock(p, requested_bytes) == 0);
        return buf;
    }

    void release() noexcept {
        if (ptr != nullptr && size > 0) {
            secure_zero(ptr, size);
            if (locked) {
                sys::direct_munlock(ptr, size);
            }
            sys::direct_munmap(ptr, size);
        }
        ptr = nullptr;
        size = 0;
        locked = false;
    }
};

}  // namespace maigveil::mem
