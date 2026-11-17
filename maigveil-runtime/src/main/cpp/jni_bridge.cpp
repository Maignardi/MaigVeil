#include "anti_tamper.hpp"
#include "apk_sig_verifier.hpp"
#include "compile_time_obf.hpp"
#include "crypto_engine.hpp"
#include "vm_engine.hpp"
#include "zero_trace_mem.hpp"

#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <array>
#include <cstring>
#include <jni.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

struct EncryptedStringEntry {
    uint32_t class_hash = 0;
    uint32_t method_hash = 0;
    uint32_t str_index = 0;
    std::vector<uint8_t> cipher;
};

std::mutex g_mutex;
bool g_initialized = false;
bool g_vault_authenticated = false;
std::array<uint8_t, 32> g_cert_sha256{};
std::array<uint8_t, 32> g_session_key{};
std::array<uint8_t, 8> g_arx_schedule{};
std::array<uint8_t, 256> g_opcode_perm{};
std::unordered_map<uint32_t, EncryptedStringEntry> g_strings;
std::unordered_map<uint32_t, maigveil::vm::VmProgram> g_vm_programs;

inline uint16_t rd_u16(const uint8_t*& p, const uint8_t* end) noexcept {
    if (p + 2 > end) { p = end; return 0; }
    uint16_t v = static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
    p += 2;
    return v;
}

inline uint32_t rd_u32(const uint8_t*& p, const uint8_t* end) noexcept {
    if (p + 4 > end) { p = end; return 0; }
    uint32_t v = static_cast<uint32_t>(p[0]) |
                 (static_cast<uint32_t>(p[1]) << 8) |
                 (static_cast<uint32_t>(p[2]) << 16) |
                 (static_cast<uint32_t>(p[3]) << 24);
    p += 4;
    return v;
}

inline int64_t rd_i64(const uint8_t*& p, const uint8_t* end) noexcept {
    if (p + 8 > end) { p = end; return 0; }
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<uint64_t>(p[i]) << (i * 8));
    }
    p += 8;
    return static_cast<int64_t>(v);
}

std::string rd_str(const uint8_t*& p, const uint8_t* end) noexcept {
    const uint16_t len = rd_u16(p, end);
    if (p + len > end) { p = end; return {}; }
    std::string s(reinterpret_cast<const char*>(p), len);
    p += len;
    return s;
}

std::string resolve_string_internal(uint32_t string_id) noexcept {
    const auto it = g_strings.find(string_id);
    if (it == g_strings.end()) {
        return {};
    }
    const auto& entry = it->second;
    std::string out(entry.cipher.size(), '\0');
    if (!entry.cipher.empty()) {
        maigveil::crypto::arx_decrypt(
            g_session_key,
            g_arx_schedule,
            entry.class_hash,
            entry.method_hash,
            entry.str_index,
            entry.cipher,
            reinterpret_cast<uint8_t*>(out.data()));
    }
    return out;
}

void parse_vault_body(const std::vector<uint8_t>& body) noexcept {
    const uint8_t* p = body.data();
    const uint8_t* end = body.data() + body.size();
    if (p + 8 + 256 + 4 > end) return;

    std::memcpy(g_arx_schedule.data(), p, 8);
    p += 8;
    std::memcpy(g_opcode_perm.data(), p, 256);
    p += 256;

    const uint32_t str_count = rd_u32(p, end);
    g_strings.reserve(str_count);
    for (uint32_t i = 0; i < str_count && p < end; ++i) {
        const uint32_t id = rd_u32(p, end);
        EncryptedStringEntry entry{};
        entry.class_hash = rd_u32(p, end);
        entry.method_hash = rd_u32(p, end);
        entry.str_index = rd_u32(p, end);
        const uint32_t clen = rd_u32(p, end);
        if (p + clen > end) break;
        entry.cipher.assign(p, p + clen);
        p += clen;
        g_strings[id] = std::move(entry);
    }

    if (p + 4 > end) return;
    const uint32_t prog_count = rd_u32(p, end);
    g_vm_programs.reserve(prog_count);
    for (uint32_t i = 0; i < prog_count && p < end; ++i) {
        maigveil::vm::VmProgram prog{};
        prog.program_id = rd_u32(p, end);
        prog.param_count = rd_u16(p, end);
        prog.max_locals = rd_u16(p, end);
        prog.max_stack = rd_u16(p, end);
        if (p + 1 > end) break;
        prog.return_type = static_cast<maigveil::vm::VmReturnType>(*p++);
        const uint16_t const_count = rd_u16(p, end);
        prog.const_pool.reserve(const_count);
        for (uint16_t c = 0; c < const_count && p < end; ++c) {
            maigveil::vm::VmConstEntry ce{};
            ce.tag = static_cast<maigveil::vm::VmConstTag>(*p++);
            switch (ce.tag) {
                case maigveil::vm::VmConstTag::INT:
                case maigveil::vm::VmConstTag::FLOAT:
                    ce.num_val = static_cast<int32_t>(rd_u32(p, end));
                    break;
                case maigveil::vm::VmConstTag::LONG:
                case maigveil::vm::VmConstTag::DOUBLE:
                    ce.num_val = rd_i64(p, end);
                    break;
                case maigveil::vm::VmConstTag::STRING_ID:
                    ce.str_id = rd_u32(p, end);
                    break;
                case maigveil::vm::VmConstTag::METHOD_REF:
                    ce.method_ref.owner = rd_str(p, end);
                    ce.method_ref.name = rd_str(p, end);
                    ce.method_ref.desc = rd_str(p, end);
                    break;
            }
            prog.const_pool.push_back(std::move(ce));
        }
        const uint32_t code_len = rd_u32(p, end);
        if (p + code_len > end) break;
        prog.bytecode.assign(p, p + code_len);
        p += code_len;
        g_vm_programs[prog.program_id] = std::move(prog);
    }
}

jboolean JNICALL native_init(JNIEnv* env, jclass, jobject asset_manager_obj) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_initialized) {
        return g_vault_authenticated ? JNI_TRUE : JNI_FALSE;
    }

    if (!asset_manager_obj) return JNI_FALSE;
    AAssetManager* mgr = AAssetManager_fromJava(env, asset_manager_obj);
    if (!mgr) return JNI_FALSE;

    const std::string vault_name = MV_OBF_STR("mv_vault.bin");
    AAsset* asset = AAssetManager_open(mgr, vault_name.c_str(), AASSET_MODE_BUFFER);
    if (!asset) {
        g_initialized = true;
        g_vault_authenticated = false;
        return JNI_FALSE;
    }

    const off_t total_len = AAsset_getLength(asset);
    if (total_len < 48 + 16) {
        AAsset_close(asset);
        g_initialized = true;
        return JNI_FALSE;
    }

    std::vector<uint8_t> raw(static_cast<size_t>(total_len));
    AAsset_read(asset, raw.data(), raw.size());
    AAsset_close(asset);

    // Header: magic "MVLT" (4B) | version (4B) | flags (4B) | reserved (4B) | buildEntropySeed (32B)
    const std::string magic = MV_OBF_STR("MVLT");
    if (std::memcmp(raw.data(), magic.data(), 4) != 0) {
        g_initialized = true;
        return JNI_FALSE;
    }

    std::array<uint8_t, 32> build_seed{};
    std::memcpy(build_seed.data(), raw.data() + 16, 32);

    // Derive K_session = HKDF-SHA256(ikm = CertSHA256 || WB_MASTER, salt = build_seed, info = "MaigVeil-v1-Session")
    const auto wb_master = maigveil::obf::extract_whitebox_master();
    std::array<uint8_t, 64> ikm{};
    std::memcpy(ikm.data(), g_cert_sha256.data(), 32);
    std::memcpy(ikm.data() + 32, wb_master.data(), 32);

    const std::string info_str = MV_OBF_STR("MaigVeil-v1-Session");
    g_session_key = maigveil::crypto::hkdf_sha256(
        ikm,
        build_seed,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()));
    maigveil::mem::secure_zero(ikm.data(), ikm.size());

    std::array<uint8_t, 12> nonce{};
    std::memcpy(nonce.data(), build_seed.data(), 12);

    const size_t body_cipher_len = raw.size() - 48 - 16;
    std::array<uint8_t, 16> tag{};
    std::memcpy(tag.data(), raw.data() + raw.size() - 16, 16);

    std::vector<uint8_t> body;
    const bool ok = maigveil::crypto::chacha20_poly1305_decrypt(
        g_session_key,
        nonce,
        std::span<const uint8_t>(raw.data(), 48),
        std::span<const uint8_t>(raw.data() + 48, body_cipher_len),
        tag,
        body);

    g_initialized = true;
    if (ok) {
        g_vault_authenticated = true;
        parse_vault_body(body);
        maigveil::mem::secure_zero(body.data(), body.size());
    } else {
        // Silent Anti-Repackaging: corrupt key/schedule deterministically without crashing
        g_vault_authenticated = false;
        for (size_t i = 0; i < 8; ++i) g_arx_schedule[i] = g_cert_sha256[i] ^ 0xA5u;
        for (size_t i = 0; i < 256; ++i) g_opcode_perm[i] = static_cast<uint8_t>(i ^ g_cert_sha256[i & 31u]);
    }
    return g_vault_authenticated ? JNI_TRUE : JNI_FALSE;
}

jstring JNICALL native_decrypt_string(JNIEnv* env, jclass, jint string_id) {
    const auto defense = maigveil::tamper::run_self_defense_checks(
        reinterpret_cast<const void*>(&native_decrypt_string));
    std::string plain = resolve_string_internal(static_cast<uint32_t>(string_id));
    if (!defense.is_clean()) {
        // Silent corruption on active hook/tamper
        for (size_t i = 0; i < plain.size(); ++i) {
            plain[i] ^= static_cast<char>(0x5Au + i);
        }
    }
    jstring ret = env->NewStringUTF(plain.c_str());
    maigveil::mem::secure_zero(plain.data(), plain.size());
    return ret;
}

jlongArray JNICALL native_alloc_zero_trace(JNIEnv* env, jclass, jint string_id) {
    std::string plain = resolve_string_internal(static_cast<uint32_t>(string_id));
    const size_t len = plain.size();
    auto buf = maigveil::mem::LockedBuffer::allocate(len > 0 ? len : 1);
    if (buf.ptr && len > 0) {
        std::memcpy(buf.ptr, plain.data(), len);
    }
    maigveil::mem::secure_zero(plain.data(), plain.size());

    jlongArray out = env->NewLongArray(2);
    jlong vals[2] = {
        reinterpret_cast<jlong>(buf.ptr),
        static_cast<jlong>(len)
    };
    env->SetLongArrayRegion(out, 0, 2, vals);
    return out;
}

jobject JNICALL native_wrap_direct_buffer(JNIEnv* env, jclass, jlong addr, jlong len) {
    if (addr == 0 || len <= 0) return nullptr;
    return env->NewDirectByteBuffer(reinterpret_cast<void*>(addr), len);
}

void JNICALL native_release_zero_trace(JNIEnv*, jclass, jlong addr, jlong len) {
    if (addr == 0) return;
    maigveil::mem::LockedBuffer buf{};
    buf.ptr = reinterpret_cast<void*>(addr);
    buf.size = static_cast<size_t>(len > 0 ? len : 1);
    buf.locked = true;
    buf.release();
}

jbyteArray JNICALL native_decrypt_asset(
    JNIEnv* env,
    jclass,
    jstring asset_path_j,
    jbyteArray encrypted_bytes_j) {
    if (!asset_path_j || !encrypted_bytes_j) return nullptr;
    const jsize total_len = env->GetArrayLength(encrypted_bytes_j);
    if (total_len < 4 + 12 + 16) return nullptr;

    std::vector<uint8_t> raw(static_cast<size_t>(total_len));
    env->GetByteArrayRegion(encrypted_bytes_j, 0, total_len, reinterpret_cast<jbyte*>(raw.data()));

    const std::string magic = MV_OBF_STR("MVAS");
    if (std::memcmp(raw.data(), magic.data(), 4) != 0) {
        return nullptr;
    }

    std::array<uint8_t, 12> nonce{};
    std::memcpy(nonce.data(), raw.data() + 4, 12);

    const char* path_c = env->GetStringUTFChars(asset_path_j, nullptr);
    const std::string info_prefix = MV_OBF_STR("MaigVeil-Asset:");
    const std::string info = info_prefix + (path_c ? path_c : "");
    if (path_c) env->ReleaseStringUTFChars(asset_path_j, path_c);

    const auto asset_key = maigveil::crypto::hkdf_sha256(
        g_session_key,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info.data()), info.size()));

    const size_t cipher_len = raw.size() - 4 - 12 - 16;
    std::array<uint8_t, 16> tag{};
    std::memcpy(tag.data(), raw.data() + raw.size() - 16, 16);

    std::vector<uint8_t> plain;
    const bool ok = maigveil::crypto::chacha20_poly1305_decrypt(
        asset_key,
        nonce,
        std::span<const uint8_t>(raw.data(), 16),
        std::span<const uint8_t>(raw.data() + 16, cipher_len),
        tag,
        plain);
    if (!ok) {
        return nullptr;
    }

    jbyteArray out = env->NewByteArray(static_cast<jsize>(plain.size()));
    if (!plain.empty()) {
        env->SetByteArrayRegion(out, 0, static_cast<jsize>(plain.size()), reinterpret_cast<const jbyte*>(plain.data()));
        maigveil::mem::secure_zero(plain.data(), plain.size());
    }
    return out;
}

maigveil::vm::VmValue run_vm_common(JNIEnv* env, jint program_id, jobjectArray args) {
    const auto defense = maigveil::tamper::run_self_defense_checks(
        reinterpret_cast<const void*>(&run_vm_common));
    const auto it = g_vm_programs.find(static_cast<uint32_t>(program_id));
    if (it == g_vm_programs.end()) {
        return maigveil::vm::VmValue{};
    }
    auto val = maigveil::vm::execute_program(
        env,
        it->second,
        g_opcode_perm,
        args,
        &resolve_string_internal);
    if (!defense.is_clean()) {
        val.i64 ^= 0x1337BEEFL;
    }
    return val;
}

jint JNICALL native_exec_vm_int(JNIEnv* env, jclass, jint program_id, jobjectArray args) {
    return static_cast<jint>(run_vm_common(env, program_id, args).i64);
}

jlong JNICALL native_exec_vm_long(JNIEnv* env, jclass, jint program_id, jobjectArray args) {
    return static_cast<jlong>(run_vm_common(env, program_id, args).i64);
}

jobject JNICALL native_exec_vm_obj(JNIEnv* env, jclass, jint program_id, jobjectArray args) {
    return run_vm_common(env, program_id, args).obj;
}

void JNICALL native_exec_vm_void(JNIEnv* env, jclass, jint program_id, jobjectArray args) {
    run_vm_common(env, program_id, args);
}

jintArray JNICALL native_get_status(JNIEnv* env, jclass) {
    const auto defense = maigveil::tamper::run_self_defense_checks(
        reinterpret_cast<const void*>(&native_get_status), true);
    jint vals[7] = {
        g_initialized ? 1 : 0,
        g_vault_authenticated ? 1 : 0,
        defense.text_integrity_ok ? 1 : 0,
        defense.no_inline_hooks ? 1 : 0,
        defense.no_debugger_attached ? 1 : 0,
        static_cast<jint>(g_strings.size()),
        static_cast<jint>(g_vm_programs.size())
    };
    jintArray out = env->NewIntArray(7);
    env->SetIntArrayRegion(out, 0, 7, vals);
    return out;
}

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || !env) {
        return JNI_ERR;
    }

    maigveil::tamper::init_self_integrity_baseline(reinterpret_cast<const void*>(&JNI_OnLoad));
    maigveil::sig::extract_apk_signing_cert_sha256(g_cert_sha256, nullptr);

    const std::string cls_name = MV_OBF_STR("io/github/maignardi/maigveil/runtime/MaigVeilNative");
    jclass cls = env->FindClass(cls_name.c_str());
    if (!cls) {
        return JNI_ERR;
    }

    const std::string m0 = MV_OBF_STR("nativeInit");
    const std::string s0 = MV_OBF_STR("(Ljava/lang/Object;)Z");
    const std::string m1 = MV_OBF_STR("nativeDecryptString");
    const std::string s1 = MV_OBF_STR("(I)Ljava/lang/String;");
    const std::string m2 = MV_OBF_STR("nativeAllocZeroTrace");
    const std::string s2 = MV_OBF_STR("(I)[J");
    const std::string m3 = MV_OBF_STR("nativeWrapDirectBuffer");
    const std::string s3 = MV_OBF_STR("(JJ)Ljava/nio/ByteBuffer;");
    const std::string m4 = MV_OBF_STR("nativeReleaseZeroTrace");
    const std::string s4 = MV_OBF_STR("(JJ)V");
    const std::string m5 = MV_OBF_STR("nativeDecryptAsset");
    const std::string s5 = MV_OBF_STR("(Ljava/lang/String;[B)[B");
    const std::string m6 = MV_OBF_STR("nativeExecVmInt");
    const std::string s6 = MV_OBF_STR("(I[Ljava/lang/Object;)I");
    const std::string m7 = MV_OBF_STR("nativeExecVmLong");
    const std::string s7 = MV_OBF_STR("(I[Ljava/lang/Object;)J");
    const std::string m8 = MV_OBF_STR("nativeExecVmObj");
    const std::string s8 = MV_OBF_STR("(I[Ljava/lang/Object;)Ljava/lang/Object;");
    const std::string m9 = MV_OBF_STR("nativeExecVmVoid");
    const std::string s9 = MV_OBF_STR("(I[Ljava/lang/Object;)V");
    const std::string m10 = MV_OBF_STR("nativeGetStatus");
    const std::string s10 = MV_OBF_STR("()[I");

    const JNINativeMethod methods[] = {
        {m0.c_str(), s0.c_str(), reinterpret_cast<void*>(&native_init)},
        {m1.c_str(), s1.c_str(), reinterpret_cast<void*>(&native_decrypt_string)},
        {m2.c_str(), s2.c_str(), reinterpret_cast<void*>(&native_alloc_zero_trace)},
        {m3.c_str(), s3.c_str(), reinterpret_cast<void*>(&native_wrap_direct_buffer)},
        {m4.c_str(), s4.c_str(), reinterpret_cast<void*>(&native_release_zero_trace)},
        {m5.c_str(), s5.c_str(), reinterpret_cast<void*>(&native_decrypt_asset)},
        {m6.c_str(), s6.c_str(), reinterpret_cast<void*>(&native_exec_vm_int)},
        {m7.c_str(), s7.c_str(), reinterpret_cast<void*>(&native_exec_vm_long)},
        {m8.c_str(), s8.c_str(), reinterpret_cast<void*>(&native_exec_vm_obj)},
        {m9.c_str(), s9.c_str(), reinterpret_cast<void*>(&native_exec_vm_void)},
        {m10.c_str(), s10.c_str(), reinterpret_cast<void*>(&native_get_status)},
    };

    if (env->RegisterNatives(cls, methods, sizeof(methods) / sizeof(methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    env->DeleteLocalRef(cls);
    return JNI_VERSION_1_6;
}
