#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace maigveil::obf {

constexpr uint32_t fnv1a_32(const char* str, uint32_t hash = 0x811c9dc5u) noexcept {
    return (*str == '\0') ? hash : fnv1a_32(str + 1, (hash ^ static_cast<uint8_t>(*str)) * 0x01000193u);
}

constexpr uint8_t rotr8(uint8_t v, unsigned r) noexcept {
    r &= 7u;
    return static_cast<uint8_t>((v >> r) | (v << ((8u - r) & 7u)));
}

constexpr uint8_t rotl8(uint8_t v, unsigned r) noexcept {
    r &= 7u;
    return static_cast<uint8_t>((v << r) | (v >> ((8u - r) & 7u)));
}

/**
 * Compile-time encrypted string container. Plaintext is never emitted into `.rodata`.
 * Decryption occurs on the stack at call sites and can be wiped immediately after use.
 */
template <std::size_t N, uint32_t Seed>
struct ObfuscatedString {
    std::array<uint8_t, N> data{};

    consteval ObfuscatedString(const char (&str)[N]) noexcept {
        uint32_t state = Seed ^ 0x9E3779B9u;
        for (std::size_t i = 0; i < N; ++i) {
            state = state * 1664525u + 1013904223u;
            const uint8_t k = static_cast<uint8_t>((state >> 16) & 0xFFu);
            const uint8_t plain = static_cast<uint8_t>(str[i]);
            data[i] = rotl8(static_cast<uint8_t>(plain ^ k), static_cast<unsigned>((i + Seed) & 7u));
        }
    }

    __attribute__((always_inline)) inline std::string decrypt() const {
        std::string out(N > 0 ? N - 1 : 0, '\0');
        uint32_t state = Seed ^ 0x9E3779B9u;
        for (std::size_t i = 0; i < N; ++i) {
            state = state * 1664525u + 1013904223u;
            const uint8_t k = static_cast<uint8_t>((state >> 16) & 0xFFu);
            const uint8_t dec = static_cast<uint8_t>(rotr8(data[i], static_cast<unsigned>((i + Seed) & 7u)) ^ k);
            if (i + 1 < N) {
                out[i] = static_cast<char>(dec);
            }
        }
        return out;
    }
};

#define MV_OBF_STR(literal) \
    ([]() -> std::string { \
        constexpr auto obf = ::maigveil::obf::ObfuscatedString< \
            sizeof(literal), \
            (::maigveil::obf::fnv1a_32(__FILE__) ^ static_cast<uint32_t>(__LINE__ * 0x45d9f3bu)) \
        >(literal); \
        return obf.decrypt(); \
    }())

/**
 * Pulverized white-box master key shares.
 * Reconstructed only in registers at runtime via always-inline bit-sliced operations
 * and combined with the APK signing certificate SHA-256 + BuildEntropySeed.
 */
template <uint64_t Share, uint64_t Mask, unsigned Rot>
__attribute__((always_inline)) inline uint64_t reconstruct_wb_lane() noexcept {
    volatile uint64_t s = Share;
    volatile uint64_t m = Mask;
    const uint64_t unmasked = s ^ m;
    return (unmasked >> Rot) | (unmasked << (64u - Rot));
}

__attribute__((always_inline)) inline std::array<uint8_t, 32> extract_whitebox_master() noexcept {
    // Canonical 256-bit MaigVeil White-Box Root:
    // Lane 0: 0x4D6169675665696CULL ("MaigVeil")
    // Lane 1: 0xA3F912C48801DE7BULL
    // Lane 2: 0x5E71B0993C44A21FULL
    // Lane 3: 0x91D84E276F05C38AULL
    const uint64_t lanes[4] = {
        reconstruct_wb_lane<0x2804963AC274CEE6ULL, 0x05287CF66F59474AULL, 13>(),
        reconstruct_wb_lane<0xFE1F26A206F0F14EULL, 0x6F1F1D6D728FD316ULL, 29>(),
        reconstruct_wb_lane<0x3AD396CA99562663ULL, 0xB397A8767A37141BULL, 41>(),
        reconstruct_wb_lane<0x6B50357A326AD66EULL, 0x1A6B4D542E3E58ACULL, 19>()
    };
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 4; ++i) {
        for (int b = 0; b < 8; ++b) {
            out[i * 8 + b] = static_cast<uint8_t>((lanes[i] >> ((7 - b) * 8)) & 0xFFu);
        }
    }
    return out;
}

}  // namespace maigveil::obf
