package io.github.maignardi.maigveil.plugin

import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import java.util.concurrent.atomic.AtomicInteger

/**
 * Pass 3: Call Indirection via `INVOKEDYNAMIC`.
 *
 * Replaces `INVOKESTATIC` and `INVOKEVIRTUAL` calls targeting sensitive APIs
 * (e.g., `javax/crypto`, `java/security`, `okhttp3`) with `INVOKEDYNAMIC`
 * bound to `MaigVeilBootstrap.bootstrap`, hiding call-graph edges from static analysis.
 */
object CallIndirectionPass {

    private val BSM_HANDLE = Handle(
        Opcodes.H_INVOKESTATIC,
        "io/github/maignardi/maigveil/runtime/MaigVeilBootstrap",
        "bootstrap",
        "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;I)Ljava/lang/invoke/CallSite;",
        false
    )

    private val counter = AtomicInteger(1)

    fun transform(
        cn: ClassNode,
        config: ResolvedMaigVeilConfig,
        collector: VaultCollector
    ): Boolean {
        if (!config.callIndirectionEnabled || config.targetApis.isEmpty()) return false
        if (AnnotationHelper.isIgnored(cn)) return false

        val classTargeted = config.isTargetClass(cn.name) ||
            AnnotationHelper.hasAnnotation(cn.invisibleAnnotations, AnnotationHelper.ANN_OBFUSCATE)

        var modified = false
        for (mn in cn.methods) {
            if (AnnotationHelper.isIgnored(mn)) continue
            if ((mn.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue

            val methodTargeted = classTargeted ||
                AnnotationHelper.hasAnnotation(mn.invisibleAnnotations, AnnotationHelper.ANN_OBFUSCATE)
            if (!methodTargeted) continue

            var cur = mn.instructions.first
            while (cur != null) {
                val next = cur.next
                if (cur is MethodInsnNode &&
                    (cur.opcode == Opcodes.INVOKESTATIC || cur.opcode == Opcodes.INVOKEVIRTUAL) &&
                    matchesTargetApi(cur.owner, cur.name, config.targetApis)
                ) {
                    val isStatic = cur.opcode == Opcodes.INVOKESTATIC
                    val spec = "${cur.owner}|${cur.name}|${cur.desc}|${if (isStatic) "S" else "V"}"
                    val encryptedSpecId = collector.registerString(cn.name, mn.name, spec)

                    val effectiveDesc = if (isStatic) {
                        cur.desc
                    } else {
                        val parsed = Type.getMethodType(cur.desc)
                        val argTypes = arrayOf(Type.getObjectType(cur.owner)) + parsed.argumentTypes
                        Type.getMethodDescriptor(parsed.returnType, *argTypes)
                    }

                    val indy = InvokeDynamicInsnNode(
                        "mv_${counter.getAndIncrement()}",
                        effectiveDesc,
                        BSM_HANDLE,
                        encryptedSpecId
                    )
                    mn.instructions.insert(cur, indy)
                    mn.instructions.remove(cur)
                    modified = true
                }
                cur = next
            }
        }
        return modified
    }

    private fun matchesTargetApi(owner: String, name: String, patterns: List<String>): Boolean {
        val full = "$owner.$name"
        return patterns.any { pat ->
            when {
                pat.endsWith("/*") -> owner.startsWith(pat.removeSuffix("*"))
                pat.endsWith("*") -> full.startsWith(pat.removeSuffix("*")) || owner.startsWith(pat.removeSuffix("*"))
                else -> owner == pat || full == pat
            }
        }
    }
}
