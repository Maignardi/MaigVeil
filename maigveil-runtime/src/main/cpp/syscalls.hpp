#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace maigveil::sys {

/**
 * Direct inline syscall wrappers to bypass PLT/GOT hooks and libc `open`/`read`/`mmap` detours
 * (e.g. Frida Interceptor on libc.so). Falls back to POSIX on non-arm64/non-x86_64 targets.
 */
#if defined(__aarch64__) && defined(__linux__)

__attribute__((always_inline)) inline long raw_syscall6(
    long num, long a0, long a1, long a2, long a3, long a4, long a5) noexcept {
    register long x8 asm("x8") = num;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    register long x4 asm("x4") = a4;
    register long x5 asm("x5") = a5;
    asm volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");
    return x0;
}

// Linux aarch64 syscall numbers (asm-generic/unistd.h)
constexpr long SYS_MV_OPENAT = 56;
constexpr long SYS_MV_CLOSE  = 57;
constexpr long SYS_MV_LSEEK  = 62;
constexpr long SYS_MV_READ   = 63;
constexpr long SYS_MV_FSTAT  = 80;
constexpr long SYS_MV_MMAP   = 222;
constexpr long SYS_MV_MUNMAP = 215;
constexpr long SYS_MV_MLOCK  = 228;
constexpr long SYS_MV_MUNLOCK = 229;

#elif defined(__x86_64__) && defined(__linux__)

__attribute__((always_inline)) inline long raw_syscall6(
    long num, long a0, long a1, long a2, long a3, long a4, long a5) noexcept {
    long ret;
    register long r10 asm("r10") = a3;
    register long r8 asm("r8") = a4;
    register long r9 asm("r9") = a5;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}

constexpr long SYS_MV_READ    = 0;
constexpr long SYS_MV_CLOSE   = 3;
constexpr long SYS_MV_FSTAT   = 5;
constexpr long SYS_MV_LSEEK   = 8;
constexpr long SYS_MV_MMAP    = 9;
constexpr long SYS_MV_MUNMAP  = 11;
constexpr long SYS_MV_MLOCK   = 149;
constexpr long SYS_MV_MUNLOCK = 150;
constexpr long SYS_MV_OPENAT  = 257;

#endif

__attribute__((always_inline)) inline int direct_open_ro(const char* path) noexcept {
#if (defined(__aarch64__) || defined(__x86_64__)) && defined(__linux__)
    long r = raw_syscall6(SYS_MV_OPENAT, AT_FDCWD, reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC, 0, 0, 0);
    return (r < 0) ? -1 : static_cast<int>(r);
#else
    return ::open(path, O_RDONLY | O_CLOEXEC);
#endif
}

__attribute__((always_inline)) inline ssize_t direct_read(int fd, void* buf, size_t count) noexcept {
#if (defined(__aarch64__) || defined(__x86_64__)) && defined(__linux__)
    long r = raw_syscall6(SYS_MV_READ, fd, reinterpret_cast<long>(buf), static_cast<long>(count), 0, 0, 0);
    return static_cast<ssize_t>(r);
#else
    return ::read(fd, buf, count);
#endif
}

__attribute__((always_inline)) inline off_t direct_lseek(int fd, off_t offset, int whence) noexcept {
#if (defined(__aarch64__) || defined(__x86_64__)) && defined(__linux__)
    long r = raw_syscall6(SYS_MV_LSEEK, fd, static_cast<long>(offset), whence, 0, 0, 0);
    return static_cast<off_t>(r);
#else
    return ::lseek(fd, offset, whence);
#endif
}

__attribute__((always_inline)) inline int direct_close(int fd) noexcept {
#if (defined(__aarch64__) || defined(__x86_64__)) && defined(__linux__)
    long r = raw_syscall6(SYS_MV_CLOSE, fd, 0, 0, 0, 0, 0);
    return static_cast<int>(r);
#else
    return ::close(fd);
#endif
}

__attribute__((always_inline)) inline void* direct_mmap_anon(size_t size) noexcept {
#if (defined(__aarch64__) || defined(__x86_64__)) && defined(__linux__)
    long r = raw_syscall6(
        SYS_MV_MMAP,
        0,
        static_cast<long>(size),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
    if (r < 0 && r > -4096) return MAP_FAILED;
    return reinterpret_cast<void*>(r);
#else
    return ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

__attribute__((always_inline)) inline int direct_munmap(void* addr, size_t size) noexcept {
#if (defined(__aarch64__) || defined(__x86_64__)) && defined(__linux__)
    long r = raw_syscall6(SYS_MV_MUNMAP, reinterpret_cast<long>(addr), static_cast<long>(size), 0, 0, 0, 0);
    return static_cast<int>(r);
#else
    return ::munmap(addr, size);
#endif
}

__attribute__((always_inline)) inline int direct_mlock(const void* addr, size_t size) noexcept {
#if (defined(__aarch64__) || defined(__x86_64__)) && defined(__linux__)
    long r = raw_syscall6(SYS_MV_MLOCK, reinterpret_cast<long>(addr), static_cast<long>(size), 0, 0, 0, 0);
    return static_cast<int>(r);
#else
    return ::mlock(addr, size);
#endif
}

__attribute__((always_inline)) inline int direct_munlock(const void* addr, size_t size) noexcept {
#if (defined(__aarch64__) || defined(__x86_64__)) && defined(__linux__)
    long r = raw_syscall6(SYS_MV_MUNLOCK, reinterpret_cast<long>(addr), static_cast<long>(size), 0, 0, 0, 0);
    return static_cast<int>(r);
#else
    return ::munlock(addr, size);
#endif
}

}  // namespace maigveil::sys
