package io.github.maignardi.maigveil.plugin

import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.IincInsnNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.VarInsnNode
import java.io.ByteArrayOutputStream

/**
 * Pass 4: Mini-VM / Bytecode Virtualization.
 *
 * Compiles methods annotated with `@VeilVirtualize` into MaigVeil's custom
 * shuffled-opcode bytecode executed by the native C++20 VM (`libmaigveil.so`).
 */
object VirtualizationPass {

    private const val VM_CLS = "io/github/maignardi/maigveil/runtime/MaigVeilVM"

    private object VmOp {
        const val NOP = 0x01
        const val CONST_I32 = 0x02
        const val CONST_I64 = 0x03
        const val CONST_STR = 0x06
        const val CONST_NULL = 0x07
        const val LOAD_LOCAL = 0x08
        const val STORE_LOCAL = 0x09
        const val LOAD_OBJ = 0x0A
        const val STORE_OBJ = 0x0B
        const val IINC = 0x0C

        const val IADD = 0x10
        const val ISUB = 0x11
        const val IMUL = 0x12
        const val IDIV = 0x13
        const val IREM = 0x14
        const val INEG = 0x15
        const val ISHL = 0x16
        const val ISHR = 0x17
        const val IUSHR = 0x18
        const val IAND = 0x19
        const val IOR = 0x1A
        const val IXOR = 0x1B

        const val LADD = 0x20
        const val LSUB = 0x21
        const val LMUL = 0x22
        const val LDIV = 0x23
        const val LREM = 0x24
        const val LNEG = 0x25
        const val LSHL = 0x26
        const val LSHR = 0x27
        const val LUSHR = 0x28
        const val LAND = 0x29
        const val LOR = 0x2A
        const val LXOR = 0x2B
        const val LCMP = 0x2C

        const val I2L = 0x30
        const val L2I = 0x31
        const val I2B = 0x32
        const val I2C = 0x33
        const val I2S = 0x34

        const val POP = 0x38
        const val DUP = 0x39
        const val SWAP = 0x3A

        const val JMP = 0x40
        const val IFEQ = 0x41
        const val IFNE = 0x42
        const val IFLT = 0x43
        const val IFGE = 0x44
        const val IFGT = 0x45
        const val IFLE = 0x46
        const val IF_ICMPEQ = 0x47
        const val IF_ICMPNE = 0x48
        const val IF_ICMPLT = 0x49
        const val IF_ICMPGE = 0x4A
        const val IF_ICMPGT = 0x4B
        const val IF_ICMPLE = 0x4C

        const val NEWARRAY = 0x50
        const val ARRAYLENGTH = 0x51
        const val IALOAD = 0x52
        const val IASTORE = 0x53
        const val BALOAD = 0x54
        const val BASTORE = 0x55
        const val CALOAD = 0x56
        const val CASTORE = 0x57
        const val LALOAD = 0x58
        const val LASTORE = 0x59

        const val CALL_STATIC = 0x60
        const val CALL_VIRTUAL = 0x61

        const val RET_VOID = 0x70
        const val RET_I32 = 0x71
        const val RET_I64 = 0x72
        const val RET_OBJ = 0x73
    }

    fun transform(
        cn: ClassNode,
        config: ResolvedMaigVeilConfig,
        seedData: BuildSeedData,
        collector: VaultCollector
    ): Boolean {
        if (!config.virtualizationEnabled) return false
        if (AnnotationHelper.isIgnored(cn)) return false

        var modified = false
        for (mn in cn.methods) {
            if (AnnotationHelper.isIgnored(mn)) continue
            if (mn.name == "<init>" || mn.name == "<clinit>") continue
            if ((mn.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
            if (!AnnotationHelper.hasAnnotation(mn.invisibleAnnotations, AnnotationHelper.ANN_VIRTUALIZE)) continue
            if (mn.tryCatchBlocks.isNotEmpty()) continue

            val compiled = compileMethod(cn.name, mn, seedData, collector) ?: continue
            collector.registerVmProgram(compiled)
            rewriteMethodStub(mn, compiled.programId)
            modified = true
        }
        return modified
    }

    private fun compileMethod(
        ownerName: String,
        mn: MethodNode,
        seedData: BuildSeedData,
        collector: VaultCollector
    ): VaultVmProgram? {
        val isStatic = (mn.access and Opcodes.ACC_STATIC) != 0
        val argTypes = Type.getArgumentTypes(mn.desc)
        val retType = Type.getReturnType(mn.desc)

        // Map JVM local slots (where long/double take 2 slots) to compact VM local slots (1 slot each)
        val jvmToVmSlot = HashMap<Int, Int>()
        var jvmSlot = 0
        var vmSlot = 0
        if (!isStatic) {
            jvmToVmSlot[jvmSlot++] = vmSlot++
        }
        for (t in argTypes) {
            jvmToVmSlot[jvmSlot] = vmSlot++
            jvmSlot += t.size
        }
        val paramCount = vmSlot
        fun mapLocal(jvmIdx: Int): Int = jvmToVmSlot.getOrPut(jvmIdx) { vmSlot++ }

        val code = ByteArrayOutputStream()
        val opOffsets = mutableListOf<Int>()
        val labelOffsets = HashMap<LabelNode, Int>()
        val patchSites = mutableListOf<Pair<Int, LabelNode>>()
        val constPool = mutableListOf<VmConstPoolEntry>()

        fun emitOp(canonicalOp: Int) {
            opOffsets += code.size()
            code.write(canonicalOp and 0xFF)
        }

        fun emitU16(v: Int) {
            code.write(v and 0xFF)
            code.write((v ushr 8) and 0xFF)
        }

        fun emitI32(v: Int) {
            code.write(v and 0xFF)
            code.write((v ushr 8) and 0xFF)
            code.write((v ushr 16) and 0xFF)
            code.write((v ushr 24) and 0xFF)
        }

        fun emitI64(v: Long) {
            for (i in 0 until 8) {
                code.write(((v ushr (i * 8)) and 0xFFL).toInt())
            }
        }

        for (insn in mn.instructions) {
            if (insn is LabelNode) {
                labelOffsets[insn] = code.size()
                continue
            }
            if (insn.opcode < 0) continue

            when (insn.opcode) {
                Opcodes.NOP -> emitOp(VmOp.NOP)
                Opcodes.ACONST_NULL -> emitOp(VmOp.CONST_NULL)
                in Opcodes.ICONST_M1..Opcodes.ICONST_5 -> {
                    emitOp(VmOp.CONST_I32)
                    emitI32(insn.opcode - Opcodes.ICONST_0)
                }
                Opcodes.LCONST_0, Opcodes.LCONST_1 -> {
                    emitOp(VmOp.CONST_I64)
                    emitI64((insn.opcode - Opcodes.LCONST_0).toLong())
                }
                Opcodes.BIPUSH, Opcodes.SIPUSH -> {
                    emitOp(VmOp.CONST_I32)
                    emitI32((insn as IntInsnNode).operand)
                }
                Opcodes.LDC -> {
                    val cst = (insn as LdcInsnNode).cst
                    when (cst) {
                        is Int -> {
                            emitOp(VmOp.CONST_I32)
                            emitI32(cst)
                        }
                        is Long -> {
                            emitOp(VmOp.CONST_I64)
                            emitI64(cst)
                        }
                        is String -> {
                            val strId = collector.registerString(ownerName, mn.name, cst)
                            val poolIdx = constPool.size
                            constPool += VmConstPoolEntry.StringId(strId)
                            emitOp(VmOp.CONST_STR)
                            emitU16(poolIdx)
                        }
                        else -> return null
                    }
                }
                Opcodes.ILOAD, Opcodes.LLOAD -> {
                    emitOp(VmOp.LOAD_LOCAL)
                    emitU16(mapLocal((insn as VarInsnNode).`var`))
                }
                Opcodes.ALOAD -> {
                    emitOp(VmOp.LOAD_OBJ)
                    emitU16(mapLocal((insn as VarInsnNode).`var`))
                }
                Opcodes.ISTORE, Opcodes.LSTORE -> {
                    emitOp(VmOp.STORE_LOCAL)
                    emitU16(mapLocal((insn as VarInsnNode).`var`))
                }
                Opcodes.ASTORE -> {
                    emitOp(VmOp.STORE_OBJ)
                    emitU16(mapLocal((insn as VarInsnNode).`var`))
                }
                Opcodes.IINC -> {
                    val iinc = insn as IincInsnNode
                    emitOp(VmOp.IINC)
                    emitU16(mapLocal(iinc.`var`))
                    emitU16(iinc.incr and 0xFFFF)
                }
                Opcodes.IADD -> emitOp(VmOp.IADD)
                Opcodes.ISUB -> emitOp(VmOp.ISUB)
                Opcodes.IMUL -> emitOp(VmOp.IMUL)
                Opcodes.IDIV -> emitOp(VmOp.IDIV)
                Opcodes.IREM -> emitOp(VmOp.IREM)
                Opcodes.INEG -> emitOp(VmOp.INEG)
                Opcodes.ISHL -> emitOp(VmOp.ISHL)
                Opcodes.ISHR -> emitOp(VmOp.ISHR)
                Opcodes.IUSHR -> emitOp(VmOp.IUSHR)
                Opcodes.IAND -> emitOp(VmOp.IAND)
                Opcodes.IOR -> emitOp(VmOp.IOR)
                Opcodes.IXOR -> emitOp(VmOp.IXOR)
                Opcodes.LADD -> emitOp(VmOp.LADD)
                Opcodes.LSUB -> emitOp(VmOp.LSUB)
                Opcodes.LMUL -> emitOp(VmOp.LMUL)
                Opcodes.LDIV -> emitOp(VmOp.LDIV)
                Opcodes.LREM -> emitOp(VmOp.LREM)
                Opcodes.LNEG -> emitOp(VmOp.LNEG)
                Opcodes.LSHL -> emitOp(VmOp.LSHL)
                Opcodes.LSHR -> emitOp(VmOp.LSHR)
                Opcodes.LUSHR -> emitOp(VmOp.LUSHR)
                Opcodes.LAND -> emitOp(VmOp.LAND)
                Opcodes.LOR -> emitOp(VmOp.LOR)
                Opcodes.LXOR -> emitOp(VmOp.LXOR)
                Opcodes.LCMP -> emitOp(VmOp.LCMP)
                Opcodes.I2L -> emitOp(VmOp.I2L)
                Opcodes.L2I -> emitOp(VmOp.L2I)
                Opcodes.I2B -> emitOp(VmOp.I2B)
                Opcodes.I2C -> emitOp(VmOp.I2C)
                Opcodes.I2S -> emitOp(VmOp.I2S)
                Opcodes.POP -> emitOp(VmOp.POP)
                Opcodes.DUP -> emitOp(VmOp.DUP)
                Opcodes.SWAP -> emitOp(VmOp.SWAP)
                Opcodes.GOTO -> {
                    emitOp(VmOp.JMP)
                    patchSites += code.size() to (insn as JumpInsnNode).label
                    emitI32(0)
                }
                in Opcodes.IFEQ..Opcodes.IF_ICMPLE -> {
                    val vmJump = when (insn.opcode) {
                        Opcodes.IFEQ -> VmOp.IFEQ
                        Opcodes.IFNE -> VmOp.IFNE
                        Opcodes.IFLT -> VmOp.IFLT
                        Opcodes.IFGE -> VmOp.IFGE
                        Opcodes.IFGT -> VmOp.IFGT
                        Opcodes.IFLE -> VmOp.IFLE
                        Opcodes.IF_ICMPEQ -> VmOp.IF_ICMPEQ
                        Opcodes.IF_ICMPNE -> VmOp.IF_ICMPNE
                        Opcodes.IF_ICMPLT -> VmOp.IF_ICMPLT
                        Opcodes.IF_ICMPGE -> VmOp.IF_ICMPGE
                        Opcodes.IF_ICMPGT -> VmOp.IF_ICMPGT
                        Opcodes.IF_ICMPLE -> VmOp.IF_ICMPLE
                        else -> return null
                    }
                    emitOp(vmJump)
                    patchSites += code.size() to (insn as JumpInsnNode).label
                    emitI32(0)
                }
                Opcodes.NEWARRAY -> {
                    emitOp(VmOp.NEWARRAY)
                    code.write((insn as IntInsnNode).operand and 0xFF)
                }
                Opcodes.ARRAYLENGTH -> emitOp(VmOp.ARRAYLENGTH)
                Opcodes.IALOAD -> emitOp(VmOp.IALOAD)
                Opcodes.IASTORE -> emitOp(VmOp.IASTORE)
                Opcodes.BALOAD -> emitOp(VmOp.BALOAD)
                Opcodes.BASTORE -> emitOp(VmOp.BASTORE)
                Opcodes.CALOAD -> emitOp(VmOp.CALOAD)
                Opcodes.CASTORE -> emitOp(VmOp.CASTORE)
                Opcodes.LALOAD -> emitOp(VmOp.LALOAD)
                Opcodes.LASTORE -> emitOp(VmOp.LASTORE)
                Opcodes.INVOKESTATIC, Opcodes.INVOKEVIRTUAL, Opcodes.INVOKEINTERFACE -> {
                    val mi = insn as MethodInsnNode
                    val poolIdx = constPool.size
                    constPool += VmConstPoolEntry.MethodRef(mi.owner, mi.name, mi.desc)
                    emitOp(if (insn.opcode == Opcodes.INVOKESTATIC) VmOp.CALL_STATIC else VmOp.CALL_VIRTUAL)
                    emitU16(poolIdx)
                }
                Opcodes.RETURN -> emitOp(VmOp.RET_VOID)
                Opcodes.IRETURN -> emitOp(VmOp.RET_I32)
                Opcodes.LRETURN -> emitOp(VmOp.RET_I64)
                Opcodes.ARETURN -> emitOp(VmOp.RET_OBJ)
                else -> return null // Unsupported instruction; graceful fallback
            }
        }

        val rawBytes = code.toByteArray()

        // Patch 4-byte branch targets
        for ((site, lbl) in patchSites) {
            val target = labelOffsets[lbl] ?: return null
            rawBytes[site] = (target and 0xFF).toByte()
            rawBytes[site + 1] = ((target ushr 8) and 0xFF).toByte()
            rawBytes[site + 2] = ((target ushr 16) and 0xFF).toByte()
            rawBytes[site + 3] = ((target ushr 24) and 0xFF).toByte()
        }

        // Encode every canonical opcode using the per-build shuffled permutation table
        for (opOff in opOffsets) {
            val canonical = rawBytes[opOff].toInt() and 0xFF
            rawBytes[opOff] = seedData.opcodeEncodeTable[canonical]
        }

        val vmRetType = when (retType.sort) {
            Type.VOID -> 0
            Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> 1
            Type.LONG -> 2
            Type.FLOAT -> 3
            Type.DOUBLE -> 4
            else -> 5
        }

        val programId = collector.allocateProgramId()
        return VaultVmProgram(
            programId = programId,
            paramCount = paramCount,
            maxLocals = maxOf(vmSlot, 8),
            maxStack = maxOf(mn.maxStack, 16),
            returnType = vmRetType,
            constPool = constPool,
            bytecode = rawBytes
        )
    }

    private fun rewriteMethodStub(mn: MethodNode, programId: Int) {
        val isStatic = (mn.access and Opcodes.ACC_STATIC) != 0
        val argTypes = Type.getArgumentTypes(mn.desc)
        val retType = Type.getReturnType(mn.desc)
        val totalArgs = argTypes.size + (if (isStatic) 0 else 1)

        val stub = InsnList()
        stub.add(LdcInsnNode(programId))
        if (totalArgs == 0) {
            stub.add(InsnNode(Opcodes.ACONST_NULL))
        } else {
            stub.add(LdcInsnNode(totalArgs))
            stub.add(org.objectweb.asm.tree.TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"))
            var arrIdx = 0
            var localIdx = 0
            if (!isStatic) {
                stub.add(InsnNode(Opcodes.DUP))
                stub.add(LdcInsnNode(arrIdx++))
                stub.add(VarInsnNode(Opcodes.ALOAD, localIdx++))
                stub.add(InsnNode(Opcodes.AASTORE))
            }
            for (t in argTypes) {
                stub.add(InsnNode(Opcodes.DUP))
                stub.add(LdcInsnNode(arrIdx++))
                when (t.sort) {
                    Type.BOOLEAN -> {
                        stub.add(VarInsnNode(Opcodes.ILOAD, localIdx))
                        stub.add(MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false))
                    }
                    Type.BYTE -> {
                        stub.add(VarInsnNode(Opcodes.ILOAD, localIdx))
                        stub.add(MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false))
                    }
                    Type.CHAR -> {
                        stub.add(VarInsnNode(Opcodes.ILOAD, localIdx))
                        stub.add(MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false))
                    }
                    Type.SHORT -> {
                        stub.add(VarInsnNode(Opcodes.ILOAD, localIdx))
                        stub.add(MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false))
                    }
                    Type.INT -> {
                        stub.add(VarInsnNode(Opcodes.ILOAD, localIdx))
                        stub.add(MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false))
                    }
                    Type.LONG -> {
                        stub.add(VarInsnNode(Opcodes.LLOAD, localIdx))
                        stub.add(MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false))
                    }
                    else -> {
                        stub.add(VarInsnNode(Opcodes.ALOAD, localIdx))
                    }
                }
                stub.add(InsnNode(Opcodes.AASTORE))
                localIdx += t.size
            }
        }

        when (retType.sort) {
            Type.VOID -> {
                stub.add(MethodInsnNode(Opcodes.INVOKESTATIC, VM_CLS, "executeVoid", "(I[Ljava/lang/Object;)V", false))
                stub.add(InsnNode(Opcodes.RETURN))
            }
            Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> {
                stub.add(MethodInsnNode(Opcodes.INVOKESTATIC, VM_CLS, "executeInt", "(I[Ljava/lang/Object;)I", false))
                if (retType.sort == Type.BYTE) stub.add(InsnNode(Opcodes.I2B))
                else if (retType.sort == Type.CHAR) stub.add(InsnNode(Opcodes.I2C))
                else if (retType.sort == Type.SHORT) stub.add(InsnNode(Opcodes.I2S))
                stub.add(InsnNode(Opcodes.IRETURN))
            }
            Type.LONG -> {
                stub.add(MethodInsnNode(Opcodes.INVOKESTATIC, VM_CLS, "executeLong", "(I[Ljava/lang/Object;)J", false))
                stub.add(InsnNode(Opcodes.LRETURN))
            }
            else -> {
                stub.add(MethodInsnNode(Opcodes.INVOKESTATIC, VM_CLS, "executeObject", "(I[Ljava/lang/Object;)Ljava/lang/Object;", false))
                if (retType.internalName != "java/lang/Object") {
                    stub.add(org.objectweb.asm.tree.TypeInsnNode(Opcodes.CHECKCAST, retType.internalName))
                }
                stub.add(InsnNode(Opcodes.ARETURN))
            }
        }

        mn.instructions = stub
        mn.localVariables = null
        mn.maxStack = 6
    }
}
