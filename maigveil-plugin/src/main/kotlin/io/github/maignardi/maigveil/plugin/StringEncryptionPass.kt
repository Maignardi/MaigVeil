package io.github.maignardi.maigveil.plugin

import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode

/**
 * Pass 1: Polymorphic String & Constant Encryption.
 *
 * 1. Strips `ConstantValue` from `static final String` fields (when `encryptConstVals` is enabled)
 *    and injects runtime decryption into `<clinit>`.
 * 2. Replaces every `LDC <String>` instruction with `MaigVeil.decryptString(stringId)`.
 */
object StringEncryptionPass {

    private const val RUNTIME_CLS = "io/github/maignardi/maigveil/runtime/MaigVeil"

    fun transform(
        cn: ClassNode,
        config: ResolvedMaigVeilConfig,
        collector: VaultCollector
    ): Boolean {
        if (!config.stringEnabled) return false
        if (AnnotationHelper.isIgnored(cn)) return false

        val classMarked = config.isTargetClass(cn.name) ||
            AnnotationHelper.hasAnnotation(cn.invisibleAnnotations, AnnotationHelper.ANN_OBFUSCATE) ||
            AnnotationHelper.hasAnnotation(cn.invisibleAnnotations, AnnotationHelper.ANN_STRING)

        var modified = false

        // 1. Handle static final String fields with ConstantValue
        if (config.encryptConstVals && classMarked) {
            val constFields = cn.fields.filter { fn ->
                !AnnotationHelper.isIgnored(fn) &&
                    (fn.access and Opcodes.ACC_STATIC) != 0 &&
                    fn.desc == "Ljava/lang/String;" &&
                    fn.value is String
            }
            if (constFields.isNotEmpty()) {
                val clinit = findOrCreateClinit(cn)
                val initInsns = InsnList()
                for (fn in constFields) {
                    val strVal = fn.value as String
                    fn.value = null // Remove ConstantValue attribute from DEX constant pool
                    val id = collector.registerString(cn.name, "<clinit>", strVal)
                    initInsns.add(LdcInsnNode(id))
                    initInsns.add(
                        MethodInsnNode(
                            Opcodes.INVOKESTATIC,
                            RUNTIME_CLS,
                            "decryptString",
                            "(I)Ljava/lang/String;",
                            false
                        )
                    )
                    initInsns.add(
                        FieldInsnNode(
                            Opcodes.PUTSTATIC,
                            cn.name,
                            fn.name,
                            fn.desc
                        )
                    )
                    modified = true
                }
                clinit.instructions.insert(initInsns)
            }
        }

        // 2. Handle LDC <String> instructions inside methods
        for (mn in cn.methods) {
            if (AnnotationHelper.isIgnored(mn)) continue
            if ((mn.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue

            val methodMarked = classMarked ||
                AnnotationHelper.hasAnnotation(mn.invisibleAnnotations, AnnotationHelper.ANN_OBFUSCATE) ||
                AnnotationHelper.hasAnnotation(mn.invisibleAnnotations, AnnotationHelper.ANN_STRING)
            if (!methodMarked) continue

            val insns = mn.instructions
            var cur = insns.first
            while (cur != null) {
                val next = cur.next
                if (cur is LdcInsnNode && cur.cst is String) {
                    val str = cur.cst as String
                    val id = collector.registerString(cn.name, mn.name, str)
                    val zeroTraceCall = findFollowingZeroTraceCall(cur)
                    if (zeroTraceCall != null) {
                        insns.insert(cur, LdcInsnNode(id))
                        insns.remove(cur)
                        zeroTraceCall.name = "withSecretId"
                        zeroTraceCall.desc = "(ILkotlin/jvm/functions/Function1;)Ljava/lang/Object;"
                    } else {
                        val replacement = InsnList().apply {
                            add(LdcInsnNode(id))
                            add(
                                MethodInsnNode(
                                    Opcodes.INVOKESTATIC,
                                    RUNTIME_CLS,
                                    "decryptString",
                                    "(I)Ljava/lang/String;",
                                    false
                                )
                            )
                        }
                        insns.insert(cur, replacement)
                        insns.remove(cur)
                    }
                    modified = true
                }
                cur = next
            }
        }

        return modified
    }

    private fun findFollowingZeroTraceCall(ldcNode: LdcInsnNode): MethodInsnNode? {
        var probe = ldcNode.next
        var steps = 0
        while (probe != null && steps < 12) {
            if (probe is MethodInsnNode &&
                probe.opcode == Opcodes.INVOKESTATIC &&
                probe.owner == RUNTIME_CLS &&
                probe.name == "withZeroTraceSecret" &&
                probe.desc == "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)Ljava/lang/Object;"
            ) {
                return probe
            }
            if (probe is LdcInsnNode && probe.cst is String) return null
            if (probe is org.objectweb.asm.tree.JumpInsnNode || probe is org.objectweb.asm.tree.LabelNode) return null
            probe = probe.next
            steps++
        }
        return null
    }

    private fun findOrCreateClinit(cn: ClassNode): MethodNode {
        val existing = cn.methods.firstOrNull { it.name == "<clinit>" && it.desc == "()V" }
        if (existing != null) return existing
        val created = MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        created.instructions.add(InsnNode(Opcodes.RETURN))
        cn.methods.add(created)
        return created
    }
}
