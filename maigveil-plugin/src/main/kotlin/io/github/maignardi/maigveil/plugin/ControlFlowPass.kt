package io.github.maignardi.maigveil.plugin

import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TableSwitchInsnNode
import org.objectweb.asm.tree.VarInsnNode
import org.objectweb.asm.tree.analysis.Analyzer
import org.objectweb.asm.tree.analysis.BasicInterpreter
import java.security.SecureRandom

/**
 * Pass 2: Control Flow Flattening & Mathematical Opaque Predicates.
 *
 * Transforms structured control flow into a `LOOKUPSWITCH`-based state machine
 * with encrypted state transitions and number-theoretic opaque predicates.
 */
object ControlFlowPass {

    private data class BasicBlock(
        val index: Int,
        val entryLabel: LabelNode,
        val insns: MutableList<AbstractInsnNode> = mutableListOf(),
        val labelsInBlock: MutableSet<LabelNode> = mutableSetOf()
    )

    fun transform(
        cn: ClassNode,
        config: ResolvedMaigVeilConfig,
        rng: SecureRandom
    ): Boolean {
        if (!config.controlFlowEnabled) return false
        if (AnnotationHelper.isIgnored(cn)) return false

        val classTargeted = config.isTargetClass(cn.name) ||
            AnnotationHelper.hasAnnotation(cn.invisibleAnnotations, AnnotationHelper.ANN_OBFUSCATE) ||
            AnnotationHelper.hasAnnotation(cn.invisibleAnnotations, AnnotationHelper.ANN_CONTROL_FLOW)

        var modified = false
        for (mn in cn.methods) {
            if (AnnotationHelper.isIgnored(mn)) continue
            if (mn.name == "<init>" || mn.name == "<clinit>") continue
            if ((mn.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE or Opcodes.ACC_SYNTHETIC)) != 0) continue
            if (AnnotationHelper.hasAnnotation(mn.invisibleAnnotations, AnnotationHelper.ANN_VIRTUALIZE)) continue
            if (mn.tryCatchBlocks.isNotEmpty()) continue

            val cfAnn = AnnotationHelper.findAnnotation(mn.invisibleAnnotations, AnnotationHelper.ANN_CONTROL_FLOW)
                ?: AnnotationHelper.findAnnotation(cn.invisibleAnnotations, AnnotationHelper.ANN_CONTROL_FLOW)

            val methodTargeted = classTargeted ||
                cfAnn != null ||
                AnnotationHelper.hasAnnotation(mn.invisibleAnnotations, AnnotationHelper.ANN_OBFUSCATE)
            if (!methodTargeted) continue

            val prob = AnnotationHelper.getIntArg(cfAnn, "flatteningProbability", config.flatteningProbability)
            val opaqueLevel = AnnotationHelper.getIntArg(cfAnn, "opaquePredicatesLevel", config.opaquePredicatesLevel)

            if (prob <= 0 && opaqueLevel <= 0) continue

            if (flattenMethod(cn.name, mn, prob, opaqueLevel, rng)) {
                modified = true
            }
        }
        return modified
    }

    private fun flattenMethod(
        ownerName: String,
        mn: MethodNode,
        flatteningProb: Int,
        opaqueLevel: Int,
        rng: SecureRandom
    ): Boolean {
        val originalInsns = mn.instructions
        if (originalInsns.size() < 6) return false

        // Verify stack depth is 0 at all jump targets so LOOKUPSWITCH dispatching is 100% frame-safe
        mn.maxLocals = maxOf(mn.maxLocals, computeNextLocalIndex(mn))
        mn.maxStack = maxOf(mn.maxStack, 8)
        val frames = try {
            Analyzer(BasicInterpreter()).analyze(ownerName, mn)
        } catch (_: Throwable) {
            return false
        }

        // Collect all jump target labels
        val jumpTargets = mutableSetOf<LabelNode>()
        for (insn in originalInsns) {
            when (insn) {
                is JumpInsnNode -> jumpTargets += insn.label
                is LookupSwitchInsnNode -> {
                    jumpTargets += insn.dflt
                    jumpTargets.addAll(insn.labels)
                }
                is TableSwitchInsnNode -> {
                    jumpTargets += insn.dflt
                    jumpTargets.addAll(insn.labels)
                }
            }
        }

        val insnArray = originalInsns.toArray()
        for (idx in insnArray.indices) {
            val insn = insnArray[idx]
            if (insn is LabelNode && insn in jumpTargets) {
                val f = frames.getOrNull(idx)
                if (f != null && f.stackSize != 0) {
                    return false
                }
            }
        }

        // Check non-parameter local variable type consistency so we can pre-initialize them before loopStart
        val paramEndSlot = computeParamEndSlot(mn)
        val localTypes = HashMap<Int, Int>() // slot -> Opcodes.ISTORE / LSTORE / FSTORE / DSTORE / ASTORE
        fun recordSlotType(slot: Int, storeOp: Int): Boolean {
            if (slot < paramEndSlot) return true
            val existing = localTypes[slot]
            if (existing != null && existing != storeOp) return false
            localTypes[slot] = storeOp
            return true
        }
        for (insn in insnArray) {
            when (insn) {
                is VarInsnNode -> {
                    val norm = when (insn.opcode) {
                        Opcodes.ILOAD, Opcodes.ISTORE -> Opcodes.ISTORE
                        Opcodes.LLOAD, Opcodes.LSTORE -> Opcodes.LSTORE
                        Opcodes.FLOAD, Opcodes.FSTORE -> Opcodes.FSTORE
                        Opcodes.DLOAD, Opcodes.DSTORE -> Opcodes.DSTORE
                        Opcodes.ALOAD, Opcodes.ASTORE -> Opcodes.ASTORE
                        else -> continue
                    }
                    if (!recordSlotType(insn.`var`, norm)) return false
                }
                is org.objectweb.asm.tree.IincInsnNode -> {
                    if (!recordSlotType(insn.`var`, Opcodes.ISTORE)) return false
                }
            }
        }

        // Partition instructions into basic blocks
        val blocks = mutableListOf<BasicBlock>()
        var currentBlock = BasicBlock(0, LabelNode())
        for (insn in originalInsns) {
            if (insn is LabelNode && insn in jumpTargets && currentBlock.insns.isNotEmpty()) {
                blocks += currentBlock
                currentBlock = BasicBlock(blocks.size, insn)
            }
            if (insn is LabelNode) {
                currentBlock.labelsInBlock += insn
            } else if (insn.opcode >= 0) { // skip LineNumberNode / FrameNode
                currentBlock.insns += insn
                if (isTerminator(insn)) {
                    blocks += currentBlock
                    currentBlock = BasicBlock(blocks.size, LabelNode())
                }
            }
        }
        if (currentBlock.insns.isNotEmpty()) {
            blocks += currentBlock
        }

        if (blocks.size < 2) return false
        if (rng.nextInt(100) >= flatteningProb) return false

        // Detach all instructions from originalInsns before re-inserting into `out`
        originalInsns.clear()

        // Map every LabelNode to its owning block index
        val labelToBlock = HashMap<LabelNode, Int>()
        for (b in blocks) {
            labelToBlock[b.entryLabel] = b.index
            for (lbl in b.labelsInBlock) {
                labelToBlock[lbl] = b.index
            }
        }

        // Compute local variable slot for stateVar and opaque scratch var
        val nextLocal = computeNextLocalIndex(mn)
        val stateVar = nextLocal
        val opaqueVar = nextLocal + 1

        // Generate bijective encrypted state IDs: enc(i) = ((i + 1) * oddMult) xor salt
        val oddMult = (rng.nextInt() or 1)
        val salt = rng.nextInt()
        fun encState(idx: Int): Int = ((idx + 1) * oddMult) xor salt

        val loopStart = LabelNode()
        val defaultTrap = LabelNode()
        val out = InsnList()

        // Pre-initialize non-parameter locals so every slot has a valid non-TOP type at LOOKUPSWITCH
        for ((slot, storeOp) in localTypes) {
            when (storeOp) {
                Opcodes.ISTORE -> { out.add(InsnNode(Opcodes.ICONST_0)); out.add(VarInsnNode(Opcodes.ISTORE, slot)) }
                Opcodes.LSTORE -> { out.add(InsnNode(Opcodes.LCONST_0)); out.add(VarInsnNode(Opcodes.LSTORE, slot)) }
                Opcodes.FSTORE -> { out.add(InsnNode(Opcodes.FCONST_0)); out.add(VarInsnNode(Opcodes.FSTORE, slot)) }
                Opcodes.DSTORE -> { out.add(InsnNode(Opcodes.DCONST_0)); out.add(VarInsnNode(Opcodes.DSTORE, slot)) }
                Opcodes.ASTORE -> { out.add(InsnNode(Opcodes.ACONST_NULL)); out.add(VarInsnNode(Opcodes.ASTORE, slot)) }
            }
        }

        // Initialize opaqueVar from non-constant runtime entropy (System.nanoTime() as int)
        // so R8 / static analyzers cannot constant-fold opaque predicates.
        out.add(
            org.objectweb.asm.tree.MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/System",
                "nanoTime",
                "()J",
                false
            )
        )
        out.add(InsnNode(Opcodes.L2I))
        out.add(LdcInsnNode(rng.nextInt()))
        out.add(InsnNode(Opcodes.IXOR))
        out.add(VarInsnNode(Opcodes.ISTORE, opaqueVar))
        out.add(LdcInsnNode(encState(0)))
        out.add(VarInsnNode(Opcodes.ISTORE, stateVar))

        out.add(loopStart)
        out.add(VarInsnNode(Opcodes.ILOAD, stateVar))

        // Build sorted LOOKUPSWITCH entries
        val switchEntries = blocks.map { b -> encState(b.index) to b.entryLabel }.sortedBy { it.first }
        val keys = switchEntries.map { it.first }.toIntArray()
        val labels = switchEntries.map { it.second }.toTypedArray()
        out.add(LookupSwitchInsnNode(defaultTrap, keys, labels))

        // Emit each flattened block
        val shuffledOrder = blocks.shuffled(rng)
        for (b in shuffledOrder) {
            out.add(b.entryLabel)

            // Optional opaque predicate injection at block entry
            if (opaqueLevel >= 1 && b.index > 0) {
                injectOpaquePredicate(out, opaqueVar, opaqueLevel, defaultTrap, rng)
            }

            val last = b.insns.lastOrNull()
            val bodyEnd = if (last != null && isTerminator(last)) b.insns.size - 1 else b.insns.size
            for (k in 0 until bodyEnd) {
                out.add(b.insns[k])
            }

            when (last) {
                is JumpInsnNode -> {
                    val targetIdx = labelToBlock[last.label]
                    if (targetIdx == null) {
                        out.add(last)
                    } else if (last.opcode == Opcodes.GOTO) {
                        out.add(LdcInsnNode(encState(targetIdx)))
                        out.add(VarInsnNode(Opcodes.ISTORE, stateVar))
                        out.add(JumpInsnNode(Opcodes.GOTO, loopStart))
                    } else {
                        val takenLabel = LabelNode()
                        val fallthroughIdx = minOf(b.index + 1, blocks.size - 1)
                        out.add(JumpInsnNode(last.opcode, takenLabel))
                        out.add(LdcInsnNode(encState(fallthroughIdx)))
                        out.add(VarInsnNode(Opcodes.ISTORE, stateVar))
                        out.add(JumpInsnNode(Opcodes.GOTO, loopStart))
                        out.add(takenLabel)
                        out.add(LdcInsnNode(encState(targetIdx)))
                        out.add(VarInsnNode(Opcodes.ISTORE, stateVar))
                        out.add(JumpInsnNode(Opcodes.GOTO, loopStart))
                    }
                }
                is LookupSwitchInsnNode -> {
                    // Rewrite switch targets to state updates
                    val newLabels = Array(last.labels.size) { LabelNode() }
                    val newDflt = LabelNode()
                    out.add(LookupSwitchInsnNode(newDflt, last.keys.toIntArray(), newLabels))
                    for (idx in last.labels.indices) {
                        val tIdx = labelToBlock[last.labels[idx]] ?: 0
                        out.add(newLabels[idx])
                        out.add(LdcInsnNode(encState(tIdx)))
                        out.add(VarInsnNode(Opcodes.ISTORE, stateVar))
                        out.add(JumpInsnNode(Opcodes.GOTO, loopStart))
                    }
                    val dIdx = labelToBlock[last.dflt] ?: 0
                    out.add(newDflt)
                    out.add(LdcInsnNode(encState(dIdx)))
                    out.add(VarInsnNode(Opcodes.ISTORE, stateVar))
                    out.add(JumpInsnNode(Opcodes.GOTO, loopStart))
                }
                is TableSwitchInsnNode -> {
                    val newLabels = Array(last.labels.size) { LabelNode() }
                    val newDflt = LabelNode()
                    out.add(TableSwitchInsnNode(last.min, last.max, newDflt, *newLabels))
                    for (idx in last.labels.indices) {
                        val tIdx = labelToBlock[last.labels[idx]] ?: 0
                        out.add(newLabels[idx])
                        out.add(LdcInsnNode(encState(tIdx)))
                        out.add(VarInsnNode(Opcodes.ISTORE, stateVar))
                        out.add(JumpInsnNode(Opcodes.GOTO, loopStart))
                    }
                    val dIdx = labelToBlock[last.dflt] ?: 0
                    out.add(newDflt)
                    out.add(LdcInsnNode(encState(dIdx)))
                    out.add(VarInsnNode(Opcodes.ISTORE, stateVar))
                    out.add(JumpInsnNode(Opcodes.GOTO, loopStart))
                }
                else -> {
                    if (last != null && isReturnOrThrow(last)) {
                        out.add(last)
                    } else if (b.index + 1 < blocks.size) {
                        out.add(LdcInsnNode(encState(b.index + 1)))
                        out.add(VarInsnNode(Opcodes.ISTORE, stateVar))
                        out.add(JumpInsnNode(Opcodes.GOTO, loopStart))
                    }
                }
            }
        }

        // Default trap block (unreachable under normal execution)
        out.add(defaultTrap)
        out.add(InsnNode(Opcodes.ACONST_NULL))
        out.add(InsnNode(Opcodes.ATHROW))

        mn.instructions = out
        mn.localVariables = null
        mn.maxLocals = maxOf(mn.maxLocals, nextLocal + 2)
        mn.maxStack = maxOf(mn.maxStack, 6)
        return true
    }

    /**
     * Injects number-theoretic opaque predicates:
     * - Level 1: `((x * (x + 1)) & 1) != 0` (impossible, product of consecutive ints is even)
     * - Level 2: `((7 * x * x - 1) & 3) == ((x * x) & 3)` (impossible mod 4)
     */
    private fun injectOpaquePredicate(
        out: InsnList,
        opaqueVar: Int,
        level: Int,
        bogusTarget: LabelNode,
        rng: SecureRandom
    ) {
        // Perturb opaqueVar with deterministic arithmetic so static constant propagation fails
        out.add(VarInsnNode(Opcodes.ILOAD, opaqueVar))
        out.add(IntInsnNode(Opcodes.BIPUSH, (rng.nextInt(127) + 1)))
        out.add(InsnNode(Opcodes.IADD))
        out.add(VarInsnNode(Opcodes.ISTORE, opaqueVar))

        // Predicate 1: (x * (x + 1)) & 1 == 0 -> if NE, jump to bogusTarget
        out.add(VarInsnNode(Opcodes.ILOAD, opaqueVar))
        out.add(VarInsnNode(Opcodes.ILOAD, opaqueVar))
        out.add(InsnNode(Opcodes.ICONST_1))
        out.add(InsnNode(Opcodes.IADD))
        out.add(InsnNode(Opcodes.IMUL))
        out.add(InsnNode(Opcodes.ICONST_1))
        out.add(InsnNode(Opcodes.IAND))
        out.add(JumpInsnNode(Opcodes.IFNE, bogusTarget))

        if (level >= 2) {
            // Predicate 2: ((7 * x * x - 1) & 3) == ((x * x) & 3) is ALWAYS FALSE
            out.add(IntInsnNode(Opcodes.BIPUSH, 7))
            out.add(VarInsnNode(Opcodes.ILOAD, opaqueVar))
            out.add(InsnNode(Opcodes.IMUL))
            out.add(VarInsnNode(Opcodes.ILOAD, opaqueVar))
            out.add(InsnNode(Opcodes.IMUL))
            out.add(InsnNode(Opcodes.ICONST_1))
            out.add(InsnNode(Opcodes.ISUB))
            out.add(InsnNode(Opcodes.ICONST_3))
            out.add(InsnNode(Opcodes.IAND))

            out.add(VarInsnNode(Opcodes.ILOAD, opaqueVar))
            out.add(VarInsnNode(Opcodes.ILOAD, opaqueVar))
            out.add(InsnNode(Opcodes.IMUL))
            out.add(InsnNode(Opcodes.ICONST_3))
            out.add(InsnNode(Opcodes.IAND))
            out.add(JumpInsnNode(Opcodes.IF_ICMPEQ, bogusTarget))
        }
    }

    private fun isTerminator(insn: AbstractInsnNode): Boolean =
        insn is JumpInsnNode ||
            insn is LookupSwitchInsnNode ||
            insn is TableSwitchInsnNode ||
            isReturnOrThrow(insn)

    private fun isReturnOrThrow(insn: AbstractInsnNode): Boolean =
        insn.opcode in Opcodes.IRETURN..Opcodes.RETURN || insn.opcode == Opcodes.ATHROW

    private fun computeParamEndSlot(mn: MethodNode): Int {
        var slot = if ((mn.access and Opcodes.ACC_STATIC) != 0) 0 else 1
        for (arg in Type.getArgumentTypes(mn.desc)) {
            slot += arg.size
        }
        return slot
    }

    private fun computeNextLocalIndex(mn: MethodNode): Int {
        var maxIdx = if ((mn.access and Opcodes.ACC_STATIC) != 0) 0 else 1
        for (arg in Type.getArgumentTypes(mn.desc)) {
            maxIdx += arg.size
        }
        for (insn in mn.instructions) {
            if (insn is VarInsnNode) {
                val end = insn.`var` + if (insn.opcode == Opcodes.LLOAD || insn.opcode == Opcodes.LSTORE ||
                    insn.opcode == Opcodes.DLOAD || insn.opcode == Opcodes.DSTORE
                ) 2 else 1
                if (end > maxIdx) maxIdx = end
            } else if (insn is org.objectweb.asm.tree.IincInsnNode) {
                if (insn.`var` + 1 > maxIdx) maxIdx = insn.`var` + 1
            }
        }
        return maxOf(maxIdx, mn.maxLocals)
    }
}
