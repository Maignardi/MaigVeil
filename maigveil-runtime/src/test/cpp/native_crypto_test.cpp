#include "../../main/cpp/compile_time_obf.hpp"
#include "../../main/cpp/crypto_engine.hpp"
#include "../../main/cpp/zero_trace_mem.hpp"

#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

static std::vector<uint8_t> hex_to_bytes(const char* hex) {
    std::vector<uint8_t> out;
    size_t len = std::strlen(hex);
    for (size_t i = 0; i + 1 < len; i += 2) {
        char buf[3] = {hex[i], hex[i + 1], '\0'};
        out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }
    return out;
}

int main() {
    // 1. Verify compile-time obfuscated string decryption
    const std::string s = MV_OBF_STR("APK Sig Block 42");
    assert(s == "APK Sig Block 42");

    // 2. Verify white-box master key reconstruction matches Kotlin MaigVeilCrypto.whiteBoxMaster()
    const auto wb = maigveil::obf::extract_whitebox_master();
    const auto expected_wb = hex_to_bytes(
        "4D6169675665696CA3F912C48801DE7B5E71B0993C44A21F91D84E276F05C38A");
    assert(std::memcmp(wb.data(), expected_wb.data(), 32) == 0);

    // 3. Verify RFC 8439 ChaCha20-Poly1305 decryption
    const auto key_vec = hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const auto nonce_vec = hex_to_bytes("070000004041424344454647");
    const auto aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
    const auto cipher = hex_to_bytes(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116");
    const auto tag_vec = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691");

    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    std::array<uint8_t, 16> tag{};
    std::memcpy(key.data(), key_vec.data(), 32);
    std::memcpy(nonce.data(), nonce_vec.data(), 12);
    std::memcpy(tag.data(), tag_vec.data(), 16);

    std::vector<uint8_t> plain_out;
    bool ok = maigveil::crypto::chacha20_poly1305_decrypt(key, nonce, aad, cipher, tag, plain_out);
    assert(ok);
    const std::string expected_plain =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    assert(std::string(plain_out.begin(), plain_out.end()) == expected_plain);

    // 4. Tampered tag must fail authentication
    auto bad_tag = tag;
    bad_tag[0] ^= 0x01;
    std::vector<uint8_t> bad_out;
    assert(!maigveil::crypto::chacha20_poly1305_decrypt(key, nonce, aad, cipher, bad_tag, bad_out));

    // 5. Zero-Trace memory allocation, wipe & release
    auto zbuf = maigveil::mem::LockedBuffer::allocate(64);
    assert(zbuf.ptr != nullptr);
    std::memset(zbuf.ptr, 0xAA, 64);
    maigveil::mem::secure_zero(zbuf.ptr, 64);
    for (int i = 0; i < 64; ++i) {
        assert(static_cast<const uint8_t*>(zbuf.ptr)[i] == 0);
    }
    zbuf.release();
    assert(zbuf.ptr == nullptr);

    std::cout << "[MaigVeil C++20] All native crypto, white-box, AEAD & zero-trace tests PASSED.\n";
    return 0;
}
