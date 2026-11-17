#include "vm_engine.hpp"
#include <cstring>
#include <mutex>
#include <vector>

namespace maigveil::vm {

namespace {

enum class VmOp : uint8_t {
    NOP         = 0x01,
    CONST_I32   = 0x02,
    CONST_I64   = 0x03,
    CONST_F32   = 0x04,
    CONST_F64   = 0x05,
    CONST_STR   = 0x06,
    CONST_NULL  = 0x07,
    LOAD_LOCAL  = 0x08,
    STORE_LOCAL = 0x09,
    LOAD_OBJ    = 0x0A,
    STORE_OBJ   = 0x0B,
    IINC        = 0x0C,

    IADD        = 0x10,
    ISUB        = 0x11,
    IMUL        = 0x12,
    IDIV        = 0x13,
    IREM        = 0x14,
    INEG        = 0x15,
    ISHL        = 0x16,
    ISHR        = 0x17,
    IUSHR       = 0x18,
    IAND        = 0x19,
    IOR         = 0x1A,
    IXOR        = 0x1B,

    LADD        = 0x20,
    LSUB        = 0x21,
    LMUL        = 0x22,
    LDIV        = 0x23,
    LREM        = 0x24,
    LNEG        = 0x25,
    LSHL        = 0x26,
    LSHR        = 0x27,
    LUSHR       = 0x28,
    LAND        = 0x29,
    LOR         = 0x2A,
    LXOR        = 0x2B,
    LCMP        = 0x2C,

    I2L         = 0x30,
    L2I         = 0x31,
    I2B         = 0x32,
    I2C         = 0x33,
    I2S         = 0x34,

    POP         = 0x38,
    DUP         = 0x39,
    SWAP        = 0x3A,

    JMP         = 0x40,
    IFEQ        = 0x41,
    IFNE        = 0x42,
    IFLT        = 0x43,
    IFGE        = 0x44,
    IFGT        = 0x45,
    IFLE        = 0x46,
    IF_ICMPEQ   = 0x47,
    IF_ICMPNE   = 0x48,
    IF_ICMPLT   = 0x49,
    IF_ICMPGE   = 0x4A,
    IF_ICMPGT   = 0x4B,
    IF_ICMPLE   = 0x4C,
    IFNULL      = 0x4D,
    IFNONNULL   = 0x4E,
    IF_ACMPEQ   = 0x4F,
    IF_ACMPNE   = 0x5A,

    NEWARRAY    = 0x50,
    ARRAYLENGTH = 0x51,
    IALOAD      = 0x52,
    IASTORE     = 0x53,
    BALOAD      = 0x54,
    BASTORE     = 0x55,
    CALOAD      = 0x56,
    CASTORE     = 0x57,
    LALOAD      = 0x58,
    LASTORE     = 0x59,

    CALL_STATIC  = 0x60,
    CALL_VIRTUAL = 0x61,

    RET_VOID    = 0x70,
    RET_I32     = 0x71,
    RET_I64     = 0x72,
    RET_OBJ     = 0x73
};

inline uint16_t rd_u16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline int16_t rd_i16(const uint8_t* p) noexcept {
    return static_cast<int16_t>(rd_u16(p));
}

inline uint32_t rd_u32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline int32_t rd_i32(const uint8_t* p) noexcept {
    return static_cast<int32_t>(rd_u32(p));
}

inline int64_t rd_i64(const uint8_t* p) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<uint64_t>(p[i]) << (i * 8));
    }
    return static_cast<int64_t>(v);
}

struct JniPrimitiveCache {
    jclass intCls = nullptr, longCls = nullptr, boolCls = nullptr;
    jclass byteCls = nullptr, shortCls = nullptr, charCls = nullptr;
    jmethodID intVal = nullptr, longVal = nullptr, boolVal = nullptr;
    jmethodID byteVal = nullptr, shortVal = nullptr, charVal = nullptr;
};

static JniPrimitiveCache g_prim_cache;
static std::once_flag g_prim_once;

static void ensure_prim_cache(JNIEnv* env) noexcept {
    std::call_once(g_prim_once, [env]() {
        auto cache_cls = [env](const char* name, const char* mname, const char* mdesc,
                               jclass& cls_out, jmethodID& mid_out) {
            jclass local = env->FindClass(name);
            if (local) {
                cls_out = static_cast<jclass>(env->NewGlobalRef(local));
                mid_out = env->GetMethodID(cls_out, mname, mdesc);
                env->DeleteLocalRef(local);
            }
        };
        cache_cls("java/lang/Integer", "intValue", "()I", g_prim_cache.intCls, g_prim_cache.intVal);
        cache_cls("java/lang/Long", "longValue", "()J", g_prim_cache.longCls, g_prim_cache.longVal);
        cache_cls("java/lang/Boolean", "booleanValue", "()Z", g_prim_cache.boolCls, g_prim_cache.boolVal);
        cache_cls("java/lang/Byte", "byteValue", "()B", g_prim_cache.byteCls, g_prim_cache.byteVal);
        cache_cls("java/lang/Short", "shortValue", "()S", g_prim_cache.shortCls, g_prim_cache.shortVal);
        cache_cls("java/lang/Character", "charValue", "()C", g_prim_cache.charCls, g_prim_cache.charVal);
    });
}

void unpack_args(JNIEnv* env, jobjectArray args, std::vector<VmValue>& locals) noexcept {
    if (!env || !args) return;
    ensure_prim_cache(env);
    const jsize len = env->GetArrayLength(args);

    for (jsize i = 0; i < len && static_cast<size_t>(i) < locals.size(); ++i) {
        jobject elem = env->GetObjectArrayElement(args, i);
        if (!elem) {
            locals[i] = VmValue{};
            continue;
        }
        if (g_prim_cache.intCls && env->IsInstanceOf(elem, g_prim_cache.intCls)) {
            locals[i].i64 = env->CallIntMethod(elem, g_prim_cache.intVal);
            env->DeleteLocalRef(elem);
        } else if (g_prim_cache.longCls && env->IsInstanceOf(elem, g_prim_cache.longCls)) {
            locals[i].i64 = env->CallLongMethod(elem, g_prim_cache.longVal);
            env->DeleteLocalRef(elem);
        } else if (g_prim_cache.boolCls && env->IsInstanceOf(elem, g_prim_cache.boolCls)) {
            locals[i].i64 = env->CallBooleanMethod(elem, g_prim_cache.boolVal) ? 1 : 0;
            env->DeleteLocalRef(elem);
        } else if (g_prim_cache.byteCls && env->IsInstanceOf(elem, g_prim_cache.byteCls)) {
            locals[i].i64 = env->CallByteMethod(elem, g_prim_cache.byteVal);
            env->DeleteLocalRef(elem);
        } else if (g_prim_cache.shortCls && env->IsInstanceOf(elem, g_prim_cache.shortCls)) {
            locals[i].i64 = env->CallShortMethod(elem, g_prim_cache.shortVal);
            env->DeleteLocalRef(elem);
        } else if (g_prim_cache.charCls && env->IsInstanceOf(elem, g_prim_cache.charCls)) {
            locals[i].i64 = env->CallCharMethod(elem, g_prim_cache.charVal);
            env->DeleteLocalRef(elem);
        } else {
            locals[i].obj = elem;
        }
    }
}

std::vector<char> parse_param_types(const std::string& desc, char& ret_type_out) noexcept {
    std::vector<char> params;
    size_t i = 1; // skip '('
    while (i < desc.size() && desc[i] != ')') {
        const char c = desc[i];
        if (c == 'L') {
            params.push_back('L');
            const size_t semi = desc.find(';', i);
            i = (semi == std::string::npos) ? desc.size() : (semi + 1);
        } else if (c == '[') {
            params.push_back('L');
            while (i < desc.size() && desc[i] == '[') ++i;
            if (i < desc.size() && desc[i] == 'L') {
                const size_t semi = desc.find(';', i);
                i = (semi == std::string::npos) ? desc.size() : (semi + 1);
            } else {
                ++i;
            }
        } else {
            params.push_back(c);
            ++i;
        }
    }
    ret_type_out = (i + 1 < desc.size()) ? desc[i + 1] : 'V';
    return params;
}

VmValue invoke_jni_method(
    JNIEnv* env,
    const VmMethodRef& mref,
    bool is_static,
    std::vector<VmValue>& stack) noexcept {
    VmValue result{};
    if (!env) return result;

    char ret_char = 'V';
    const auto ptypes = parse_param_types(mref.desc, ret_char);
    const size_t nparams = ptypes.size();
    if (stack.size() < nparams + (is_static ? 0u : 1u)) return result;

    std::vector<jvalue> jargs(nparams);
    for (size_t idx = nparams; idx > 0; --idx) {
        const VmValue v = stack.back();
        stack.pop_back();
        const char t = ptypes[idx - 1];
        switch (t) {
            case 'Z': jargs[idx - 1].z = (v.i64 != 0) ? JNI_TRUE : JNI_FALSE; break;
            case 'B': jargs[idx - 1].b = static_cast<jbyte>(v.i64); break;
            case 'C': jargs[idx - 1].c = static_cast<jchar>(v.i64); break;
            case 'S': jargs[idx - 1].s = static_cast<jshort>(v.i64); break;
            case 'I': jargs[idx - 1].i = static_cast<jint>(v.i64); break;
            case 'J': jargs[idx - 1].j = static_cast<jlong>(v.i64); break;
            default:  jargs[idx - 1].l = v.obj; break;
        }
    }

    jobject receiver = nullptr;
    if (!is_static) {
        receiver = stack.back().obj;
        stack.pop_back();
    }

    jclass cls = env->FindClass(mref.owner.c_str());
    if (!cls) return result;

    jmethodID mid = is_static
        ? env->GetStaticMethodID(cls, mref.name.c_str(), mref.desc.c_str())
        : env->GetMethodID(cls, mref.name.c_str(), mref.desc.c_str());

    if (mid) {
        if (is_static) {
            switch (ret_char) {
                case 'V': env->CallStaticVoidMethodA(cls, mid, jargs.data()); break;
                case 'Z': result.i64 = env->CallStaticBooleanMethodA(cls, mid, jargs.data()) ? 1 : 0; break;
                case 'B': result.i64 = env->CallStaticByteMethodA(cls, mid, jargs.data()); break;
                case 'C': result.i64 = env->CallStaticCharMethodA(cls, mid, jargs.data()); break;
                case 'S': result.i64 = env->CallStaticShortMethodA(cls, mid, jargs.data()); break;
                case 'I': result.i64 = env->CallStaticIntMethodA(cls, mid, jargs.data()); break;
                case 'J': result.i64 = env->CallStaticLongMethodA(cls, mid, jargs.data()); break;
                default:  result.obj = env->CallStaticObjectMethodA(cls, mid, jargs.data()); break;
            }
        } else if (receiver) {
            switch (ret_char) {
                case 'V': env->CallVoidMethodA(receiver, mid, jargs.data()); break;
                case 'Z': result.i64 = env->CallBooleanMethodA(receiver, mid, jargs.data()) ? 1 : 0; break;
                case 'B': result.i64 = env->CallByteMethodA(receiver, mid, jargs.data()); break;
                case 'C': result.i64 = env->CallCharMethodA(receiver, mid, jargs.data()); break;
                case 'S': result.i64 = env->CallShortMethodA(receiver, mid, jargs.data()); break;
                case 'I': result.i64 = env->CallIntMethodA(receiver, mid, jargs.data()); break;
                case 'J': result.i64 = env->CallLongMethodA(receiver, mid, jargs.data()); break;
                default:  result.obj = env->CallObjectMethodA(receiver, mid, jargs.data()); break;
            }
        }
    }

    env->DeleteLocalRef(cls);
    return result;
}

}  // namespace

VmValue execute_program(
    JNIEnv* env,
    const VmProgram& prog,
    const std::array<uint8_t, 256>& opcode_perm,
    jobjectArray args,
    StringResolverFn resolve_str) noexcept {
    std::vector<VmValue> locals(std::max<size_t>(prog.max_locals, 8));
    std::vector<VmValue> stack;
    stack.reserve(std::max<size_t>(prog.max_stack, 16));

    unpack_args(env, args, locals);

    const uint8_t* code = prog.bytecode.data();
    const size_t code_len = prog.bytecode.size();
    size_t pc = 0;
    size_t steps = 0;
    constexpr size_t MAX_VM_STEPS = 1000000;

    auto pop = [&]() noexcept -> VmValue {
        if (stack.empty()) return VmValue{};
        VmValue v = stack.back();
        stack.pop_back();
        return v;
    };

    auto push_i64 = [&](int64_t v) noexcept {
        VmValue val{};
        val.i64 = v;
        stack.push_back(val);
    };

    auto push_obj = [&](jobject o) noexcept {
        VmValue val{};
        val.obj = o;
        stack.push_back(val);
    };

    while (pc < code_len && steps++ < MAX_VM_STEPS) {
        const uint8_t shuffled = code[pc++];
        const VmOp op = static_cast<VmOp>(opcode_perm[shuffled]);

        switch (op) {
            case VmOp::NOP:
                break;
            case VmOp::CONST_I32: {
                if (pc + 4 > code_len) return VmValue{};
                push_i64(rd_i32(code + pc));
                pc += 4;
                break;
            }
            case VmOp::CONST_I64: {
                if (pc + 8 > code_len) return VmValue{};
                push_i64(rd_i64(code + pc));
                pc += 8;
                break;
            }
            case VmOp::CONST_STR: {
                if (pc + 2 > code_len) return VmValue{};
                const uint16_t idx = rd_u16(code + pc);
                pc += 2;
                if (idx < prog.const_pool.size() && resolve_str && env) {
                    const std::string s = resolve_str(prog.const_pool[idx].str_id);
                    push_obj(env->NewStringUTF(s.c_str()));
                } else {
                    push_obj(nullptr);
                }
                break;
            }
            case VmOp::CONST_NULL:
                push_obj(nullptr);
                break;
            case VmOp::LOAD_LOCAL:
            case VmOp::LOAD_OBJ: {
                if (pc + 2 > code_len) return VmValue{};
                const uint16_t idx = rd_u16(code + pc);
                pc += 2;
                stack.push_back(idx < locals.size() ? locals[idx] : VmValue{});
                break;
            }
            case VmOp::STORE_LOCAL:
            case VmOp::STORE_OBJ: {
                if (pc + 2 > code_len) return VmValue{};
                const uint16_t idx = rd_u16(code + pc);
                pc += 2;
                const VmValue v = pop();
                if (idx < locals.size()) locals[idx] = v;
                break;
            }
            case VmOp::IINC: {
                if (pc + 4 > code_len) return VmValue{};
                const uint16_t idx = rd_u16(code + pc);
                const int16_t delta = rd_i16(code + pc + 2);
                pc += 4;
                if (idx < locals.size()) {
                    locals[idx].i64 = static_cast<int32_t>(locals[idx].i64) + delta;
                }
                break;
            }
            case VmOp::IADD: {
                const int32_t b = static_cast<int32_t>(pop().i64);
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(static_cast<int32_t>(static_cast<uint32_t>(a) + static_cast<uint32_t>(b)));
                break;
            }
            case VmOp::ISUB: {
                const int32_t b = static_cast<int32_t>(pop().i64);
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(static_cast<int32_t>(static_cast<uint32_t>(a) - static_cast<uint32_t>(b)));
                break;
            }
            case VmOp::IMUL: {
                const int32_t b = static_cast<int32_t>(pop().i64);
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(static_cast<int32_t>(static_cast<uint32_t>(a) * static_cast<uint32_t>(b)));
                break;
            }
            case VmOp::IDIV: {
                const int32_t b = static_cast<int32_t>(pop().i64);
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(b == 0 ? 0 : (a / b));
                break;
            }
            case VmOp::IREM: {
                const int32_t b = static_cast<int32_t>(pop().i64);
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(b == 0 ? 0 : (a % b));
                break;
            }
            case VmOp::INEG: {
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(static_cast<int32_t>(-static_cast<uint32_t>(a)));
                break;
            }
            case VmOp::ISHL: {
                const uint32_t s = static_cast<uint32_t>(pop().i64) & 31u;
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(static_cast<int32_t>(static_cast<uint32_t>(a) << s));
                break;
            }
            case VmOp::ISHR: {
                const uint32_t s = static_cast<uint32_t>(pop().i64) & 31u;
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(a >> s);
                break;
            }
            case VmOp::IUSHR: {
                const uint32_t s = static_cast<uint32_t>(pop().i64) & 31u;
                const uint32_t a = static_cast<uint32_t>(pop().i64);
                push_i64(static_cast<int32_t>(a >> s));
                break;
            }
            case VmOp::IAND: {
                const int32_t b = static_cast<int32_t>(pop().i64);
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(a & b);
                break;
            }
            case VmOp::IOR: {
                const int32_t b = static_cast<int32_t>(pop().i64);
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(a | b);
                break;
            }
            case VmOp::IXOR: {
                const int32_t b = static_cast<int32_t>(pop().i64);
                const int32_t a = static_cast<int32_t>(pop().i64);
                push_i64(a ^ b);
                break;
            }
            case VmOp::LADD: {
                const int64_t b = pop().i64;
                const int64_t a = pop().i64;
                push_i64(static_cast<int64_t>(static_cast<uint64_t>(a) + static_cast<uint64_t>(b)));
                break;
            }
            case VmOp::LSUB: {
                const int64_t b = pop().i64;
                const int64_t a = pop().i64;
                push_i64(static_cast<int64_t>(static_cast<uint64_t>(a) - static_cast<uint64_t>(b)));
                break;
            }
            case VmOp::LMUL: {
                const int64_t b = pop().i64;
                const int64_t a = pop().i64;
                push_i64(static_cast<int64_t>(static_cast<uint64_t>(a) * static_cast<uint64_t>(b)));
                break;
            }
            case VmOp::LDIV: {
                const int64_t b = pop().i64;
                const int64_t a = pop().i64;
                push_i64(b == 0 ? 0 : (a / b));
                break;
            }
            case VmOp::LREM: {
                const int64_t b = pop().i64;
                const int64_t a = pop().i64;
                push_i64(b == 0 ? 0 : (a % b));
                break;
            }
            case VmOp::LNEG: {
                const int64_t a = pop().i64;
                push_i64(static_cast<int64_t>(-static_cast<uint64_t>(a)));
                break;
            }
            case VmOp::LSHL: {
                const uint32_t s = static_cast<uint32_t>(pop().i64) & 63u;
                const int64_t a = pop().i64;
                push_i64(static_cast<int64_t>(static_cast<uint64_t>(a) << s));
                break;
            }
            case VmOp::LSHR: {
                const uint32_t s = static_cast<uint32_t>(pop().i64) & 63u;
                const int64_t a = pop().i64;
                push_i64(a >> s);
                break;
            }
            case VmOp::LUSHR: {
                const uint32_t s = static_cast<uint32_t>(pop().i64) & 63u;
                const uint64_t a = static_cast<uint64_t>(pop().i64);
                push_i64(static_cast<int64_t>(a >> s));
                break;
            }
            case VmOp::LAND: {
                const int64_t b = pop().i64;
                const int64_t a = pop().i64;
                push_i64(a & b);
                break;
            }
            case VmOp::LOR: {
                const int64_t b = pop().i64;
                const int64_t a = pop().i64;
                push_i64(a | b);
                break;
            }
            case VmOp::LXOR: {
                const int64_t b = pop().i64;
                const int64_t a = pop().i64;
                push_i64(a ^ b);
                break;
            }
            case VmOp::LCMP: {
                const int64_t b = pop().i64;
                const int64_t a = pop().i64;
                push_i64(a > b ? 1 : (a < b ? -1 : 0));
                break;
            }
            case VmOp::I2L:
                push_i64(static_cast<int64_t>(static_cast<int32_t>(pop().i64)));
                break;
            case VmOp::L2I:
                push_i64(static_cast<int32_t>(pop().i64));
                break;
            case VmOp::I2B:
                push_i64(static_cast<int8_t>(pop().i64));
                break;
            case VmOp::I2C:
                push_i64(static_cast<uint16_t>(pop().i64));
                break;
            case VmOp::I2S:
                push_i64(static_cast<int16_t>(pop().i64));
                break;
            case VmOp::POP:
                pop();
                break;
            case VmOp::DUP:
                if (!stack.empty()) stack.push_back(stack.back());
                break;
            case VmOp::SWAP:
                if (stack.size() >= 2) {
                    std::swap(stack[stack.size() - 1], stack[stack.size() - 2]);
                }
                break;
            case VmOp::JMP: {
                if (pc + 4 > code_len) return VmValue{};
                const uint32_t target = rd_u32(code + pc);
                pc = target;
                break;
            }
            case VmOp::IFEQ:
            case VmOp::IFNE:
            case VmOp::IFLT:
            case VmOp::IFGE:
            case VmOp::IFGT:
            case VmOp::IFLE: {
                if (pc + 4 > code_len) return VmValue{};
                const uint32_t target = rd_u32(code + pc);
                pc += 4;
                const int32_t v = static_cast<int32_t>(pop().i64);
                bool take = false;
                if (op == VmOp::IFEQ) take = (v == 0);
                else if (op == VmOp::IFNE) take = (v != 0);
                else if (op == VmOp::IFLT) take = (v < 0);
                else if (op == VmOp::IFGE) take = (v >= 0);
                else if (op == VmOp::IFGT) take = (v > 0);
                else if (op == VmOp::IFLE) take = (v <= 0);
                if (take) pc = target;
                break;
            }
            case VmOp::IF_ICMPEQ:
            case VmOp::IF_ICMPNE:
            case VmOp::IF_ICMPLT:
            case VmOp::IF_ICMPGE:
            case VmOp::IF_ICMPGT:
            case VmOp::IF_ICMPLE: {
                if (pc + 4 > code_len) return VmValue{};
                const uint32_t target = rd_u32(code + pc);
                pc += 4;
                const int32_t b = static_cast<int32_t>(pop().i64);
                const int32_t a = static_cast<int32_t>(pop().i64);
                bool take = false;
                if (op == VmOp::IF_ICMPEQ) take = (a == b);
                else if (op == VmOp::IF_ICMPNE) take = (a != b);
                else if (op == VmOp::IF_ICMPLT) take = (a < b);
                else if (op == VmOp::IF_ICMPGE) take = (a >= b);
                else if (op == VmOp::IF_ICMPGT) take = (a > b);
                else if (op == VmOp::IF_ICMPLE) take = (a <= b);
                if (take) pc = target;
                break;
            }
            case VmOp::IFNULL:
            case VmOp::IFNONNULL: {
                if (pc + 4 > code_len) return VmValue{};
                const uint32_t target = rd_u32(code + pc);
                pc += 4;
                jobject obj = pop().obj;
                const bool is_null = (obj == nullptr);
                if ((op == VmOp::IFNULL && is_null) || (op == VmOp::IFNONNULL && !is_null)) {
                    pc = target;
                }
                break;
            }
            case VmOp::IF_ACMPEQ:
            case VmOp::IF_ACMPNE: {
                if (pc + 4 > code_len) return VmValue{};
                const uint32_t target = rd_u32(code + pc);
                pc += 4;
                jobject b = pop().obj;
                jobject a = pop().obj;
                const bool eq = (a == b) || (env && a && b && env->IsSameObject(a, b));
                if ((op == VmOp::IF_ACMPEQ && eq) || (op == VmOp::IF_ACMPNE && !eq)) {
                    pc = target;
                }
                break;
            }
            case VmOp::NEWARRAY: {
                if (pc + 1 > code_len || !env) return VmValue{};
                const uint8_t atype = code[pc++];
                const jsize len = static_cast<jsize>(pop().i64);
                jobject arr = nullptr;
                if (atype == 8) arr = env->NewByteArray(len);
                else if (atype == 5) arr = env->NewCharArray(len);
                else if (atype == 10) arr = env->NewIntArray(len);
                else if (atype == 11) arr = env->NewLongArray(len);
                push_obj(arr);
                break;
            }
            case VmOp::ARRAYLENGTH: {
                jobject arr = pop().obj;
                push_i64((arr && env) ? env->GetArrayLength(static_cast<jarray>(arr)) : 0);
                break;
            }
            case VmOp::IALOAD: {
                const jsize idx = static_cast<jsize>(pop().i64);
                auto arr = static_cast<jintArray>(pop().obj);
                jint val = 0;
                if (arr && env) env->GetIntArrayRegion(arr, idx, 1, &val);
                push_i64(val);
                break;
            }
            case VmOp::IASTORE: {
                const jint val = static_cast<jint>(pop().i64);
                const jsize idx = static_cast<jsize>(pop().i64);
                auto arr = static_cast<jintArray>(pop().obj);
                if (arr && env) env->SetIntArrayRegion(arr, idx, 1, &val);
                break;
            }
            case VmOp::BALOAD: {
                const jsize idx = static_cast<jsize>(pop().i64);
                auto arr = static_cast<jbyteArray>(pop().obj);
                jbyte val = 0;
                if (arr && env) env->GetByteArrayRegion(arr, idx, 1, &val);
                push_i64(val);
                break;
            }
            case VmOp::BASTORE: {
                const jbyte val = static_cast<jbyte>(pop().i64);
                const jsize idx = static_cast<jsize>(pop().i64);
                auto arr = static_cast<jbyteArray>(pop().obj);
                if (arr && env) env->SetByteArrayRegion(arr, idx, 1, &val);
                break;
            }
            case VmOp::CALOAD: {
                const jsize idx = static_cast<jsize>(pop().i64);
                auto arr = static_cast<jcharArray>(pop().obj);
                jchar val = 0;
                if (arr && env) env->GetCharArrayRegion(arr, idx, 1, &val);
                push_i64(val);
                break;
            }
            case VmOp::CASTORE: {
                const jchar val = static_cast<jchar>(pop().i64);
                const jsize idx = static_cast<jsize>(pop().i64);
                auto arr = static_cast<jcharArray>(pop().obj);
                if (arr && env) env->SetCharArrayRegion(arr, idx, 1, &val);
                break;
            }
            case VmOp::LALOAD: {
                const jsize idx = static_cast<jsize>(pop().i64);
                auto arr = static_cast<jlongArray>(pop().obj);
                jlong val = 0;
                if (arr && env) env->GetLongArrayRegion(arr, idx, 1, &val);
                push_i64(val);
                break;
            }
            case VmOp::LASTORE: {
                const jlong val = static_cast<jlong>(pop().i64);
                const jsize idx = static_cast<jsize>(pop().i64);
                auto arr = static_cast<jlongArray>(pop().obj);
                if (arr && env) env->SetLongArrayRegion(arr, idx, 1, &val);
                break;
            }
            case VmOp::CALL_STATIC:
            case VmOp::CALL_VIRTUAL: {
                if (pc + 2 > code_len) return VmValue{};
                const uint16_t idx = rd_u16(code + pc);
                pc += 2;
                if (idx < prog.const_pool.size() && prog.const_pool[idx].tag == VmConstTag::METHOD_REF) {
                    const auto& mref = prog.const_pool[idx].method_ref;
                    char ret_char = 'V';
                    parse_param_types(mref.desc, ret_char);
                    const VmValue res = invoke_jni_method(env, mref, op == VmOp::CALL_STATIC, stack);
                    if (ret_char != 'V') {
                        stack.push_back(res);
                    }
                }
                break;
            }
            case VmOp::RET_VOID:
                return VmValue{};
            case VmOp::RET_I32:
            case VmOp::RET_I64:
            case VmOp::RET_OBJ:
                return pop();
            default:
                return VmValue{};
        }
    }
    return VmValue{};
}

}  // namespace maigveil::vm
