#include "apk_sig_verifier.hpp"
#include "compile_time_obf.hpp"
#include "crypto_engine.hpp"
#include "syscalls.hpp"
#include <algorithm>
#include <cstring>
#include <vector>

namespace maigveil::sig {

namespace {

inline uint16_t rd_le16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t rd_le32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t rd_le64(const uint8_t* p) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<uint64_t>(p[i]) << (i * 8));
    }
    return v;
}

bool find_base_apk_path(std::string& path_out) noexcept {
    const std::string maps_path = MV_OBF_STR("/proc/self/maps");
    const int fd = sys::direct_open_ro(maps_path.c_str());
    if (fd < 0) return false;

    std::string content;
    char buf[4096];
    ssize_t n;
    while ((n = sys::direct_read(fd, buf, sizeof(buf))) > 0) {
        content.append(buf, static_cast<size_t>(n));
    }
    sys::direct_close(fd);

    const std::string ext_apk = MV_OBF_STR(".apk");
    const std::string base_apk = MV_OBF_STR("base.apk");
    size_t pos = 0;
    std::string fallback_apk;

    while (pos < content.size()) {
        size_t nl = content.find('\n', pos);
        if (nl == std::string::npos) nl = content.size();
        const std::string line = content.substr(pos, nl - pos);
        pos = nl + 1;

        const size_t slash = line.find('/');
        if (slash == std::string::npos) continue;
        const std::string candidate = line.substr(slash);
        if (candidate.size() >= ext_apk.size() &&
            candidate.compare(candidate.size() - ext_apk.size(), ext_apk.size(), ext_apk) == 0) {
            if (candidate.find(base_apk) != std::string::npos) {
                path_out = candidate;
                return true;
            }
            if (fallback_apk.empty()) {
                fallback_apk = candidate;
            }
        }
    }

    if (!fallback_apk.empty()) {
        path_out = fallback_apk;
        return true;
    }
    return false;
}

bool read_exact_at(int fd, off_t offset, uint8_t* dst, size_t len) noexcept {
    if (sys::direct_lseek(fd, offset, SEEK_SET) < 0) return false;
    size_t total = 0;
    while (total < len) {
        const ssize_t r = sys::direct_read(fd, dst + total, len - total);
        if (r <= 0) return false;
        total += static_cast<size_t>(r);
    }
    return true;
}

/**
 * Parses the first X.509 certificate from an APK Signature Scheme v2 (0x7109871a)
 * or v3 (0xf05368c0) block value.
 * Layout:
 *   signers (length-prefixed uint32)
 *     signer (length-prefixed uint32)
 *       signed_data (length-prefixed uint32)
 *         digests (length-prefixed uint32)
 *         certificates (length-prefixed uint32)
 *           cert0 (length-prefixed uint32 -> X.509 DER bytes)
 */
bool extract_first_cert_from_scheme_block(
    const uint8_t* data,
    size_t len,
    std::vector<uint8_t>& cert_out) noexcept {
    if (len < 20) return false;
    size_t off = 0;
    const uint32_t signers_len = rd_le32(data + off); off += 4;
    if (off + signers_len > len || signers_len < 12) return false;

    const uint32_t signer_len = rd_le32(data + off); off += 4;
    if (off + signer_len > len || signer_len < 8) return false;

    const uint32_t signed_data_len = rd_le32(data + off); off += 4;
    if (off + signed_data_len > len || signed_data_len < 8) return false;

    const size_t signed_end = off + signed_data_len;
    const uint32_t digests_len = rd_le32(data + off); off += 4;
    if (off + digests_len > signed_end) return false;
    off += digests_len;

    if (off + 4 > signed_end) return false;
    const uint32_t certs_len = rd_le32(data + off); off += 4;
    if (off + certs_len > signed_end || certs_len < 4) return false;

    const uint32_t first_cert_len = rd_le32(data + off); off += 4;
    if (first_cert_len == 0 || off + first_cert_len > signed_end) return false;

    cert_out.assign(data + off, data + off + first_cert_len);
    return true;
}

}  // namespace

bool extract_apk_signing_cert_sha256(
    std::array<uint8_t, 32>& sha256_out,
    std::string* apk_path_out) noexcept {
    std::string apk_path;
    if (!find_base_apk_path(apk_path)) {
        return false;
    }
    if (apk_path_out) {
        *apk_path_out = apk_path;
    }

    const int fd = sys::direct_open_ro(apk_path.c_str());
    if (fd < 0) return false;

    const off_t file_size = sys::direct_lseek(fd, 0, SEEK_END);
    if (file_size < 22) {
        sys::direct_close(fd);
        return false;
    }

    // Locate ZIP End of Central Directory (EOCD: 0x06054b50) in last 65KB + 22 bytes
    const size_t tail_len = static_cast<size_t>(std::min<off_t>(file_size, 65536 + 22));
    std::vector<uint8_t> tail(tail_len);
    if (!read_exact_at(fd, file_size - static_cast<off_t>(tail_len), tail.data(), tail_len)) {
        sys::direct_close(fd);
        return false;
    }

    off_t eocd_off = -1;
    for (size_t i = tail_len - 22; ; --i) {
        if (tail[i] == 0x50 && tail[i + 1] == 0x4b && tail[i + 2] == 0x05 && tail[i + 3] == 0x06) {
            const uint16_t comment_len = rd_le16(tail.data() + i + 20);
            if (i + 22 + comment_len == tail_len) {
                eocd_off = file_size - static_cast<off_t>(tail_len) + static_cast<off_t>(i);
                break;
            }
        }
        if (i == 0) break;
    }
    if (eocd_off < 0) {
        sys::direct_close(fd);
        return false;
    }

    // Central Directory offset is at EOCD + 16
    const size_t eocd_in_tail = static_cast<size_t>(eocd_off - (file_size - static_cast<off_t>(tail_len)));
    const uint32_t cd_offset = rd_le32(tail.data() + eocd_in_tail + 16);
    if (cd_offset < 32 || static_cast<off_t>(cd_offset) >= eocd_off) {
        sys::direct_close(fd);
        return false;
    }

    // APK Signing Block footer (24 bytes immediately before Central Directory):
    //   uint64_t size_of_block_excluding_first_8_bytes
    //   char magic[16] = "APK Sig Block 42"
    uint8_t footer[24];
    if (!read_exact_at(fd, static_cast<off_t>(cd_offset) - 24, footer, 24)) {
        sys::direct_close(fd);
        return false;
    }

    const std::string expected_magic = MV_OBF_STR("APK Sig Block 42");
    if (std::memcmp(footer + 8, expected_magic.data(), 16) != 0) {
        sys::direct_close(fd);
        return false;
    }

    const uint64_t block_size_excl_prefix = rd_le64(footer);
    if (block_size_excl_prefix < 24 || block_size_excl_prefix > 16 * 1024 * 1024) {
        sys::direct_close(fd);
        return false;
    }
    const off_t block_start = static_cast<off_t>(cd_offset) - 8 - static_cast<off_t>(block_size_excl_prefix);
    if (block_start < 0) {
        sys::direct_close(fd);
        return false;
    }

    std::vector<uint8_t> sig_block(static_cast<size_t>(block_size_excl_prefix + 8));
    if (!read_exact_at(fd, block_start, sig_block.data(), sig_block.size())) {
        sys::direct_close(fd);
        return false;
    }
    sys::direct_close(fd);

    // Verify prefix uint64 == suffix uint64
    if (rd_le64(sig_block.data()) != block_size_excl_prefix) {
        return false;
    }

    // Iterate ID-value pairs between offset 8 and (sig_block.size() - 24)
    size_t pos = 8;
    const size_t pairs_end = sig_block.size() - 24;
    std::vector<uint8_t> cert_der;

    constexpr uint32_t APK_SIG_SCHEME_V2_ID = 0x7109871Au;
    constexpr uint32_t APK_SIG_SCHEME_V3_ID = 0xF05368C0u;

    while (pos + 12 <= pairs_end) {
        const uint64_t pair_len = rd_le64(sig_block.data() + pos);
        pos += 8;
        if (pair_len < 4 || pos + pair_len > pairs_end) break;
        const uint32_t id = rd_le32(sig_block.data() + pos);
        const uint8_t* val = sig_block.data() + pos + 4;
        const size_t val_len = static_cast<size_t>(pair_len - 4);
        pos += static_cast<size_t>(pair_len);

        if (id == APK_SIG_SCHEME_V3_ID || id == APK_SIG_SCHEME_V2_ID) {
            if (extract_first_cert_from_scheme_block(val, val_len, cert_der)) {
                sha256_out = crypto::sha256(cert_der);
                return true;
            }
        }
    }

    return false;
}

}  // namespace maigveil::sig
