#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace maigveil::crypto {

std::array<uint8_t, 32> sha256(std::span<const uint8_t> data) noexcept;

std::array<uint8_t, 32> hmac_sha256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data) noexcept;

std::array<uint8_t, 32> hkdf_sha256(
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info) noexcept;

/**
 * RFC 8439 ChaCha20-Poly1305 AEAD decryption.
 * Returns true if Poly1305 authentication tag matches; false otherwise.
 */
bool chacha20_poly1305_decrypt(
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 12>& nonce,
    std::span<const uint8_t> aad,
    std::span<const uint8_t> ciphertext,
    const std::array<uint8_t, 16>& tag,
    std::vector<uint8_t>& plaintext_out) noexcept;

/**
 * Polymorphic ARX inverse transform for encrypted strings and constants.
 */
void arx_decrypt(
    const std::array<uint8_t, 32>& session_key,
    const std::array<uint8_t, 8>& schedule,
    uint32_t class_hash,
    uint32_t method_hash,
    uint32_t string_index,
    std::span<const uint8_t> ciphertext,
    uint8_t* out_buf) noexcept;

}  // namespace maigveil::crypto
