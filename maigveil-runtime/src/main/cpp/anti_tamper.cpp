#include "anti_tamper.hpp"
#include "compile_time_obf.hpp"
#include "syscalls.hpp"
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#if defined(__linux__)
#include <elf.h>
#endif

namespace maigveil::tamper {

namespace {

std::atomic<uint32_t> g_baseline_crc{0};
std::atomic<uintptr_t> g_text_start{0};
std::atomic<size_t> g_text_size{0};
std::atomic<uint64_t> g_check_counter{0};
std::atomic<bool> g_last_full_clean{true};

constexpr auto make_crc32_table() noexcept {
    std::array<uint32_t, 256> tbl{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int b = 0; b < 8; ++b) {
            c = (c & 1u) ? ((c >> 1) ^ 0xEDB88320u) : (c >> 1);
        }
        tbl[i] = c;
    }
    return tbl;
}

constexpr auto CRC32_TABLE = make_crc32_table();

uint32_t crc32_compute(const uint8_t* data, size_t len) noexcept {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc = (crc >> 8) ^ CRC32_TABLE[(crc ^ data[i]) & 0xFFu];
    }
    return ~crc;
}

bool locate_elf_exec_segment(const void* anchor_fn, uintptr_t& start_out, size_t& size_out) noexcept {
#if defined(__linux__)
    Dl_info info{};
    if (dladdr(anchor_fn, &info) == 0 || info.dli_fbase == nullptr) {
        return false;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
#if defined(__LP64__)
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return false;
    const auto* phdr = reinterpret_cast<const Elf64_Phdr*>(base + ehdr->e_phoff);
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X) != 0) {
            start_out = base + phdr[i].p_vaddr;
            size_out = static_cast<size_t>(phdr[i].p_memsz);
            return true;
        }
    }
#else
    const auto* ehdr = reinterpret_cast<const Elf32_Ehdr*>(base);
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return false;
    const auto* phdr = reinterpret_cast<const Elf32_Phdr*>(base + ehdr->e_phoff);
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X) != 0) {
            start_out = base + phdr[i].p_vaddr;
            size_out = static_cast<size_t>(phdr[i].p_memsz);
            return true;
        }
    }
#endif
#endif
    (void)anchor_fn; (void)start_out; (void)size_out;
    return false;
}

bool has_inline_hook_prologue(const void* fn_ptr) noexcept {
    if (!fn_ptr) return false;
#if defined(__aarch64__)
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn_ptr);
    const uint32_t insn0 = *reinterpret_cast<const uint32_t*>(p);
    const uint32_t insn1 = *reinterpret_cast<const uint32_t*>(p + 4);
    // Frida/Dobby ARM64 trampoline: LDR X16, #8 (0x58000050) + BR X16 (0xD61F0200)
    // or LDR X17, #8 (0x58000051) + BR X17 (0xD61F0220)
    if ((insn0 == 0x58000050u && insn1 == 0xD61F0200u) ||
        (insn0 == 0x58000051u && insn1 == 0xD61F0220u)) {
        return true;
    }
    // Unconditional branch B imm26 (0x14xxxxxx..0x17xxxxxx) at prologue
    if ((insn0 & 0xFC000000u) == 0x14000000u) {
        return true;
    }
#elif defined(__x86_64__)
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn_ptr);
    // JMP rel32 (0xE9) or JMP [rip+0] (0xFF 0x25) or INT3 (0xCC)
    if (p[0] == 0xE9 || p[0] == 0xCC || (p[0] == 0xFF && p[1] == 0x25)) {
        return true;
    }
#endif
    return false;
}

bool check_maps_no_instrumentation() noexcept {
    const std::string maps_path = MV_OBF_STR("/proc/self/maps");
    const int fd = sys::direct_open_ro(maps_path.c_str());
    if (fd < 0) return true;

    const std::string f1 = MV_OBF_STR("frida-agent");
    const std::string f2 = MV_OBF_STR("frida-gadget");
    const std::string f3 = MV_OBF_STR("libxposed");

    char buf[4096];
    ssize_t n;
    while ((n = sys::direct_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        if (std::strstr(buf, f1.c_str()) ||
            std::strstr(buf, f2.c_str()) ||
            std::strstr(buf, f3.c_str())) {
            sys::direct_close(fd);
            return false;
        }
    }
    sys::direct_close(fd);
    return true;
}

bool check_tracer_pid_zero() noexcept {
    const std::string status_path = MV_OBF_STR("/proc/self/status");
    const int fd = sys::direct_open_ro(status_path.c_str());
    if (fd < 0) return true;

    char buf[2048];
    const ssize_t n = sys::direct_read(fd, buf, sizeof(buf) - 1);
    sys::direct_close(fd);
    if (n <= 0) return true;
    buf[n] = '\0';

    const std::string needle = MV_OBF_STR("TracerPid:");
    const char* found = std::strstr(buf, needle.c_str());
    if (!found) return true;
    found += needle.size();
    while (*found == ' ' || *found == '\t') ++found;
    return (*found == '0');
}

}  // namespace

void init_self_integrity_baseline(const void* anchor_fn) noexcept {
    uintptr_t start = 0;
    size_t sz = 0;
    if (locate_elf_exec_segment(anchor_fn, start, sz) && sz > 0) {
        g_text_start.store(start, std::memory_order_relaxed);
        g_text_size.store(sz, std::memory_order_relaxed);
        const uint32_t crc = crc32_compute(reinterpret_cast<const uint8_t*>(start), sz);
        g_baseline_crc.store(crc, std::memory_order_release);
    }
}

TamperReport run_self_defense_checks(const void* probe_fn, bool full_scan) noexcept {
    TamperReport report{};
    // Always run O(1) inline hook prologue check (<2ns)
    const bool hook_free = !has_inline_hook_prologue(probe_fn);
    report.no_inline_hooks = hook_free;

    const uint64_t tick = g_check_counter.fetch_add(1, std::memory_order_relaxed);
    if (!full_scan && (tick & 63u) != 0u) {
        const bool cached_ok = g_last_full_clean.load(std::memory_order_acquire);
        report.text_integrity_ok = cached_ok;
        report.no_debugger_attached = cached_ok;
        return report;
    }

    const uintptr_t start = g_text_start.load(std::memory_order_acquire);
    const size_t sz = g_text_size.load(std::memory_order_acquire);
    const uint32_t expected = g_baseline_crc.load(std::memory_order_acquire);
    if (start != 0 && sz > 0 && expected != 0) {
        const uint32_t current = crc32_compute(reinterpret_cast<const uint8_t*>(start), sz);
        report.text_crc32 = current;
        report.text_integrity_ok = (current == expected);
    }
    report.no_inline_hooks = hook_free && check_maps_no_instrumentation();
    report.no_debugger_attached = check_tracer_pid_zero();
    g_last_full_clean.store(
        report.text_integrity_ok && report.no_inline_hooks && report.no_debugger_attached,
        std::memory_order_release);
    return report;
}

}  // namespace maigveil::tamper
