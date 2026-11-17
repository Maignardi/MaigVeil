#include "crypto_engine.hpp"
#include "zero_trace_mem.hpp"
#include <algorithm>
#include <cstring>

namespace maigveil::crypto {

namespace {

constexpr uint32_t rotr32(uint32_t v, unsigned n) noexcept {
    n &= 31u;
    return (v >> n) | (v << ((32u - n) & 31u));
}

constexpr uint32_t rotl32(uint32_t v, unsigned n) noexcept {
    n &= 31u;
    return (v << n) | (v >> ((32u - n) & 31u));
}

constexpr uint8_t rotl8(uint8_t v, unsigned n) noexcept {
    n &= 7u;
    return static_cast<uint8_t>((v << n) | (v >> ((8u - n) & 7u)));
}

constexpr uint8_t rotr8(uint8_t v, unsigned n) noexcept {
    n &= 7u;
    return static_cast<uint8_t>((v >> n) | (v << ((8u - n) & 7u)));
}

inline uint32_t load_be32(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

inline uint32_t load_le32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline void store_be32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

inline void store_le32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

inline void store_le64(uint8_t* p, uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFFu);
    }
}

constexpr std::array<uint32_t, 64> SHA256_K = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

struct Sha256Ctx {
    uint32_t state[8]{
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint64_t bitlen = 0;
    uint8_t buf[64]{};
    size_t buflen = 0;

    void transform(const uint8_t block[64]) noexcept {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = load_be32(block + i * 4);
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            const uint32_t ch = (e & f) ^ ((~e) & g);
            const uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
            const uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temp2 = S0 + maj;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void update(const uint8_t* data, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            buf[buflen++] = data[i];
            if (buflen == 64) {
                transform(buf);
                bitlen += 512;
                buflen = 0;
            }
        }
    }

    std::array<uint8_t, 32> finish() noexcept {
        uint64_t total_bits = bitlen + buflen * 8;
        buf[buflen++] = 0x80;
        if (buflen > 56) {
            while (buflen < 64) buf[buflen++] = 0;
            transform(buf);
            buflen = 0;
        }
        while (buflen < 56) buf[buflen++] = 0;
        for (int i = 0; i < 8; ++i) {
            buf[56 + i] = static_cast<uint8_t>((total_bits >> ((7 - i) * 8)) & 0xFFu);
        }
        transform(buf);
        std::array<uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i) {
            store_be32(out.data() + i * 4, state[i]);
        }
        mem::secure_zero(buf, sizeof(buf));
        return out;
    }
};

void chacha20_block(
    const std::array<uint8_t, 32>& key,
    uint32_t counter,
    const std::array<uint8_t, 12>& nonce,
    uint8_t out[64]) noexcept {
    uint32_t st[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        load_le32(key.data() + 0),  load_le32(key.data() + 4),
        load_le32(key.data() + 8),  load_le32(key.data() + 12),
        load_le32(key.data() + 16), load_le32(key.data() + 20),
        load_le32(key.data() + 24), load_le32(key.data() + 28),
        counter,
        load_le32(nonce.data() + 0), load_le32(nonce.data() + 4), load_le32(nonce.data() + 8)
    };
    uint32_t x[16];
    std::memcpy(x, st, sizeof(x));

    auto qr = [&](int a, int b, int c, int d) {
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);
    };

    for (int i = 0; i < 10; ++i) {
        qr(0, 4, 8, 12);  qr(1, 5, 9, 13);  qr(2, 6, 10, 14); qr(3, 7, 11, 15);
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13);  qr(3, 4, 9, 14);
    }
    for (int i = 0; i < 16; ++i) {
        store_le32(out + i * 4, x[i] + st[i]);
    }
    mem::secure_zero(x, sizeof(x));
}

struct Poly1305 {
    uint32_t r[5]{};
    uint32_t h[5]{};
    uint32_t pad[4]{};

    explicit Poly1305(const uint8_t key32[32]) noexcept {
        r[0] = (load_le32(key32 + 0)) & 0x3ffffffu;
        r[1] = (load_le32(key32 + 3) >> 2) & 0x3ffff03u;
        r[2] = (load_le32(key32 + 6) >> 4) & 0x3ffc0ffu;
        r[3] = (load_le32(key32 + 9) >> 6) & 0x3f03fffu;
        r[4] = (load_le32(key32 + 12) >> 8) & 0x00fffffu;
        pad[0] = load_le32(key32 + 16);
        pad[1] = load_le32(key32 + 20);
        pad[2] = load_le32(key32 + 24);
        pad[3] = load_le32(key32 + 28);
    }

    void block(const uint8_t* m, size_t len, bool is_final_partial = false) noexcept {
        uint8_t tmp[16]{};
        std::memcpy(tmp, m, len);
        const uint32_t hibit = is_final_partial ? 0u : (1u << 24);
        if (is_final_partial && len < 16) {
            tmp[len] = 1;
        }
        h[0] += (load_le32(tmp + 0)) & 0x3ffffffu;
        h[1] += (load_le32(tmp + 3) >> 2) & 0x3ffffffu;
        h[2] += (load_le32(tmp + 6) >> 4) & 0x3ffffffu;
        h[3] += (load_le32(tmp + 9) >> 6) & 0x3ffffffu;
        h[4] += (load_le32(tmp + 12) >> 8) | hibit;

        const uint64_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
        const uint64_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

        const uint64_t d0 = h[0]*r0 + h[1]*s4 + h[2]*s3 + h[3]*s2 + h[4]*s1;
        const uint64_t d1 = h[0]*r1 + h[1]*r0 + h[2]*s4 + h[3]*s3 + h[4]*s2;
        const uint64_t d2 = h[0]*r2 + h[1]*r1 + h[2]*r0 + h[3]*s4 + h[4]*s3;
        const uint64_t d3 = h[0]*r3 + h[1]*r2 + h[2]*r1 + h[3]*r0 + h[4]*s4;
        const uint64_t d4 = h[0]*r4 + h[1]*r3 + h[2]*r2 + h[3]*r1 + h[4]*r0;

        uint64_t c;
        c = d0 >> 26; h[0] = static_cast<uint32_t>(d0) & 0x3ffffffu;
        uint64_t t1 = d1 + c; c = t1 >> 26; h[1] = static_cast<uint32_t>(t1) & 0x3ffffffu;
        uint64_t t2 = d2 + c; c = t2 >> 26; h[2] = static_cast<uint32_t>(t2) & 0x3ffffffu;
        uint64_t t3 = d3 + c; c = t3 >> 26; h[3] = static_cast<uint32_t>(t3) & 0x3ffffffu;
        uint64_t t4 = d4 + c; c = t4 >> 26; h[4] = static_cast<uint32_t>(t4) & 0x3ffffffu;
        h[0] += static_cast<uint32_t>(c * 5);
        c = h[0] >> 26; h[0] &= 0x3ffffffu;
        h[1] += static_cast<uint32_t>(c);
    }

    void update(const uint8_t* data, size_t len) noexcept {
        size_t off = 0;
        while (off + 16 <= len) {
            block(data + off, 16, false);
            off += 16;
        }
        if (off < len) {
            block(data + off, len - off, true);
        }
    }

    void update_padded(std::span<const uint8_t> data) noexcept {
        if (data.empty()) return;
        size_t off = 0;
        while (off + 16 <= data.size()) {
            block(data.data() + off, 16, false);
            off += 16;
        }
        if (off < data.size()) {
            uint8_t padded[16]{};
            std::memcpy(padded, data.data() + off, data.size() - off);
            block(padded, 16, false);
        }
    }

    std::array<uint8_t, 16> finish() noexcept {
        uint32_t c = h[1] >> 26; h[1] &= 0x3ffffffu;
        h[2] += c; c = h[2] >> 26; h[2] &= 0x3ffffffu;
        h[3] += c; c = h[3] >> 26; h[3] &= 0x3ffffffu;
        h[4] += c; c = h[4] >> 26; h[4] &= 0x3ffffffu;
        h[0] += c * 5; c = h[0] >> 26; h[0] &= 0x3ffffffu;
        h[1] += c;

        uint32_t g[5];
        g[0] = h[0] + 5; c = g[0] >> 26; g[0] &= 0x3ffffffu;
        g[1] = h[1] + c; c = g[1] >> 26; g[1] &= 0x3ffffffu;
        g[2] = h[2] + c; c = g[2] >> 26; g[2] &= 0x3ffffffu;
        g[3] = h[3] + c; c = g[3] >> 26; g[3] &= 0x3ffffffu;
        g[4] = h[4] + c - (1u << 26);

        const uint32_t mask = (g[4] >> 31) - 1u;
        for (int i = 0; i < 5; ++i) {
            h[i] = (h[i] & ~mask) | (g[i] & mask);
        }

        const uint32_t f0 = (h[0]) | (h[1] << 26);
        const uint32_t f1 = (h[1] >> 6) | (h[2] << 20);
        const uint32_t f2 = (h[2] >> 12) | (h[3] << 14);
        const uint32_t f3 = (h[3] >> 18) | (h[4] << 8);

        uint64_t acc = static_cast<uint64_t>(f0) + pad[0];
        const uint32_t out0 = static_cast<uint32_t>(acc);
        acc = static_cast<uint64_t>(f1) + pad[1] + (acc >> 32);
        const uint32_t out1 = static_cast<uint32_t>(acc);
        acc = static_cast<uint64_t>(f2) + pad[2] + (acc >> 32);
        const uint32_t out2 = static_cast<uint32_t>(acc);
        acc = static_cast<uint64_t>(f3) + pad[3] + (acc >> 32);
        const uint32_t out3 = static_cast<uint32_t>(acc);

        std::array<uint8_t, 16> tag{};
        store_le32(tag.data() + 0, out0);
        store_le32(tag.data() + 4, out1);
        store_le32(tag.data() + 8, out2);
        store_le32(tag.data() + 12, out3);
        return tag;
    }
};

}  // namespace

std::array<uint8_t, 32> sha256(std::span<const uint8_t> data) noexcept {
    Sha256Ctx ctx;
    if (!data.empty()) {
        ctx.update(data.data(), data.size());
    }
    return ctx.finish();
}

std::array<uint8_t, 32> hmac_sha256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data) noexcept {
    uint8_t k_pad[64]{};
    if (key.size() > 64) {
        auto h = sha256(key);
        std::memcpy(k_pad, h.data(), 32);
    } else if (!key.empty()) {
        std::memcpy(k_pad, key.data(), key.size());
    }

    uint8_t i_pad[64];
    uint8_t o_pad[64];
    for (int i = 0; i < 64; ++i) {
        i_pad[i] = k_pad[i] ^ 0x36u;
        o_pad[i] = k_pad[i] ^ 0x5cu;
    }

    Sha256Ctx inner;
    inner.update(i_pad, 64);
    if (!data.empty()) inner.update(data.data(), data.size());
    auto inner_hash = inner.finish();

    Sha256Ctx outer;
    outer.update(o_pad, 64);
    outer.update(inner_hash.data(), 32);
    auto result = outer.finish();

    mem::secure_zero(k_pad, sizeof(k_pad));
    mem::secure_zero(i_pad, sizeof(i_pad));
    mem::secure_zero(o_pad, sizeof(o_pad));
    return result;
}

std::array<uint8_t, 32> hkdf_sha256(
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info) noexcept {
    std::array<uint8_t, 32> zero_salt{};
    std::span<const uint8_t> effective_salt = salt.empty() ? std::span<const uint8_t>(zero_salt) : salt;
    auto prk = hmac_sha256(effective_salt, ikm);

    std::vector<uint8_t> t_in(info.size() + 1);
    if (!info.empty()) {
        std::memcpy(t_in.data(), info.data(), info.size());
    }
    t_in[info.size()] = 0x01;
    auto okm = hmac_sha256(prk, t_in);
    mem::secure_zero(prk.data(), prk.size());
    return okm;
}

bool chacha20_poly1305_decrypt(
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 12>& nonce,
    std::span<const uint8_t> aad,
    std::span<const uint8_t> ciphertext,
    const std::array<uint8_t, 16>& tag,
    std::vector<uint8_t>& plaintext_out) noexcept {
    uint8_t poly_key_block[64];
    chacha20_block(key, 0, nonce, poly_key_block);

    Poly1305 poly(poly_key_block);
    mem::secure_zero(poly_key_block, sizeof(poly_key_block));

    poly.update_padded(aad);
    poly.update_padded(ciphertext);
    uint8_t lengths[16];
    store_le64(lengths + 0, static_cast<uint64_t>(aad.size()));
    store_le64(lengths + 8, static_cast<uint64_t>(ciphertext.size()));
    poly.update(lengths, 16);

    const auto computed_tag = poly.finish();
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= (computed_tag[i] ^ tag[i]);
    }
    if (diff != 0) {
        return false;
    }

    plaintext_out.resize(ciphertext.size());
    uint8_t keystream[64];
    uint32_t counter = 1;
    size_t off = 0;
    while (off < ciphertext.size()) {
        chacha20_block(key, counter++, nonce, keystream);
        const size_t chunk = std::min<size_t>(64, ciphertext.size() - off);
        for (size_t i = 0; i < chunk; ++i) {
            plaintext_out[off + i] = ciphertext[off + i] ^ keystream[i];
        }
        off += chunk;
    }
    mem::secure_zero(keystream, sizeof(keystream));
    return true;
}

void arx_decrypt(
    const std::array<uint8_t, 32>& session_key,
    const std::array<uint8_t, 8>& schedule,
    uint32_t class_hash,
    uint32_t method_hash,
    uint32_t string_index,
    std::span<const uint8_t> ciphertext,
    uint8_t* out_buf) noexcept {
    uint32_t key_words[8];
    for (int w = 0; w < 8; ++w) {
        key_words[w] = load_le32(session_key.data() + w * 4);
    }

    for (size_t i = 0; i < ciphertext.size(); ++i) {
        const uint32_t k_raw =
            key_words[i & 7u] ^
            (class_hash * 0x9E3779B1u) ^
            (method_hash * 0x85EBCA6Bu) ^
            (string_index * 0xC2B2AE35u) ^
            static_cast<uint32_t>(i);
        const uint32_t k = rotl32(k_raw, static_cast<unsigned>(i & 31u));
        const uint8_t k_byte = static_cast<uint8_t>(k & 0xFFu);

        uint8_t x = ciphertext[i];
        // Apply inverse schedule in reverse order (7 down to 0)
        for (int s = 7; s >= 0; --s) {
            const uint8_t op_byte = schedule[s];
            const uint8_t op_type = (op_byte >> 5) & 0x07u;
            const uint8_t param = op_byte & 0x1Fu;
            switch (op_type % 6u) {
                case 0:
                    x = static_cast<uint8_t>((x - ((k_byte + param) & 0xFFu)) & 0xFFu);
                    break;
                case 1:
                    x = static_cast<uint8_t>(x ^ ((k_byte ^ param) & 0xFFu));
                    break;
                case 2:
                    x = rotr8(x, param & 7u);
                    break;
                case 3:
                    x = rotl8(x, param & 7u);
                    break;
                case 4:
                    x = static_cast<uint8_t>((x - ((static_cast<uint32_t>(i) * (param | 1u)) & 0xFFu)) & 0xFFu);
                    break;
                case 5:
                default:
                    x = static_cast<uint8_t>(x ^ ((k >> (param & 24u)) & 0xFFu));
                    break;
            }
        }
        out_buf[i] = x;
    }
    mem::secure_zero(key_words, sizeof(key_words));
}

}  // namespace maigveil::crypto
