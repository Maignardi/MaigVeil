#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace maigveil::sig {

/**
 * Extracts the APK's X.509 signing certificate (APK Signature Scheme v2 / v3)
 * directly from disk using inline syscalls (bypassing PackageManager / libc hooks)
 * and computes its SHA-256 digest.
 */
bool extract_apk_signing_cert_sha256(
    std::array<uint8_t, 32>& sha256_out,
    std::string* apk_path_out = nullptr) noexcept;

}  // namespace maigveil::sig
