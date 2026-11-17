#pragma once

#include <array>
#include <cstdint>
#include <jni.h>
#include <string>
#include <vector>

namespace maigveil::vm {

enum class VmReturnType : uint8_t {
    VOID   = 0,
    INT    = 1,
    LONG   = 2,
    FLOAT  = 3,
    DOUBLE = 4,
    OBJECT = 5
};

enum class VmConstTag : uint8_t {
    INT        = 1,
    LONG       = 2,
    FLOAT      = 3,
    DOUBLE     = 4,
    STRING_ID  = 5,
    METHOD_REF = 6
};

struct VmMethodRef {
    std::string owner;  // slash-separated internal name, e.g. "java/lang/String"
    std::string name;
    std::string desc;
};

struct VmConstEntry {
    VmConstTag tag = VmConstTag::INT;
    int64_t num_val = 0;
    uint32_t str_id = 0;
    VmMethodRef method_ref{};
};

struct VmProgram {
    uint32_t program_id = 0;
    uint16_t param_count = 0;
    uint16_t max_locals = 0;
    uint16_t max_stack = 0;
    VmReturnType return_type = VmReturnType::VOID;
    std::vector<VmConstEntry> const_pool;
    std::vector<uint8_t> bytecode;
};

struct VmValue {
    int64_t i64 = 0;
    jobject obj = nullptr;
};

using StringResolverFn = std::string (*)(uint32_t str_id);

/**
 * Executes a virtualized MaigVeil program inside the C++20 interpreter
 * using the per-build shuffled opcode permutation table.
 */
VmValue execute_program(
    JNIEnv* env,
    const VmProgram& prog,
    const std::array<uint8_t, 256>& opcode_perm,
    jobjectArray args,
    StringResolverFn resolve_str) noexcept;

}  // namespace maigveil::vm
