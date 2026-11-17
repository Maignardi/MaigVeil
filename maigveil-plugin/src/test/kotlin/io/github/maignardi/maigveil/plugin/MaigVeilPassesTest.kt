package io.github.maignardi.maigveil.plugin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AnnotationNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.VarInsnNode
import java.security.SecureRandom

class MaigVeilPassesTest {

    private fun testConfig() = ResolvedMaigVeilConfig(
        enabled = true,
        profile = VeilProfile.PARANOID,
        targetPackages = listOf("com.example.core"),
        excludePackages = emptyList(),
        stringEnabled = true,
        encryptConstVals = true,
        zeroTraceMode = true,
        controlFlowEnabled = true,
        flatteningProbability = 100,
        opaquePredicatesLevel = 2,
        callIndirectionEnabled = true,
        targetApis = listOf("javax/crypto/*", "java/security/*"),
        virtualizationEnabled = true,
        encryptAssets = listOf("config/*.json"),
        bindApkSigningCertSha256 = "AUTO_EXTRACT_FROM_SIGNING_CONFIG",
        stripKotlinMetadata = true,
        stripAnnotations = true
    )

    private fun testSeed(): BuildSeedData =
        BuildSeedData.generate(ByteArray(32) { it.toByte() }, SecureRandom())

    @Test
    fun `string encryption strips ConstantValue and rewrites LDC`() {
        val cn = ClassNode().apply {
            version = Opcodes.V11
            access = Opcodes.ACC_PUBLIC
            name = "com/example/core/Secrets"
            superName = "java/lang/Object"
            fields.add(
                FieldNode(
                    Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL,
                    "API_KEY",
                    "Ljava/lang/String;",
                    null,
                    "sk_live_super_secret"
                )
            )
            methods.add(
                MethodNode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "getToken", "()Ljava/lang/String;", null, null).apply {
                    instructions.add(LdcInsnNode("bearer_12345"))
                    instructions.add(InsnNode(Opcodes.ARETURN))
                }
            )
        }

        val collector = VaultCollector(testSeed())
        val changed = StringEncryptionPass.transform(cn, testConfig(), collector)

        assertTrue(changed)
        assertNull("ConstantValue must be cleared", cn.fields[0].value)
        assertEquals(2, collector.strings.size)
        val clinit = cn.methods.firstOrNull { it.name == "<clinit>" }
        assertNotNull("<clinit> must be generated", clinit)
        val getToken = cn.methods.first { it.name == "getToken" }
        assertFalse(getToken.instructions.any { it is LdcInsnNode && it.cst is String })
        assertTrue(getToken.instructions.any { it is MethodInsnNode && it.name == "decryptString" })
    }

    @Test
    fun `control flow flattening produces valid executable bytecode`() {
        val cn = ClassNode().apply {
            version = Opcodes.V11
            access = Opcodes.ACC_PUBLIC
            name = "com/example/core/MathCheck"
            superName = "java/lang/Object"
            methods.add(
                MethodNode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "compute", "(I)I", null, null).apply {
                    val elseLbl = LabelNode()
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 0))
                    instructions.add(LdcInsnNode(10))
                    instructions.add(JumpInsnNode(Opcodes.IF_ICMPLE, elseLbl))
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 0))
                    instructions.add(LdcInsnNode(2))
                    instructions.add(InsnNode(Opcodes.IMUL))
                    instructions.add(InsnNode(Opcodes.IRETURN))
                    instructions.add(elseLbl)
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 0))
                    instructions.add(LdcInsnNode(5))
                    instructions.add(InsnNode(Opcodes.IADD))
                    instructions.add(InsnNode(Opcodes.IRETURN))
                }
            )
        }

        val changed = ControlFlowPass.transform(cn, testConfig(), SecureRandom())
        assertTrue(changed)
        val compute = cn.methods.first { it.name == "compute" }
        assertTrue(compute.instructions.any { it is LookupSwitchInsnNode })

        // Verify valid stack map frames & execute in a dynamic ClassLoader
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        cn.accept(cw)
        val bytes = cw.toByteArray()
        ClassReader(bytes)

        val loader = object : ClassLoader(this::class.java.classLoader) {
            fun define(name: String, b: ByteArray): Class<*> = defineClass(name, b, 0, b.size)
        }
        val cls = loader.define("com.example.core.MathCheck", bytes)
        val m = cls.getMethod("compute", Int::class.javaPrimitiveType)
        assertEquals(24, m.invoke(null, 12))
        assertEquals(8, m.invoke(null, 3))
    }

    @Test
    fun `call indirection rewrites javax crypto to INVOKEDYNAMIC`() {
        val cn = ClassNode().apply {
            version = Opcodes.V11
            access = Opcodes.ACC_PUBLIC
            name = "com/example/core/CryptoUser"
            superName = "java/lang/Object"
            methods.add(
                MethodNode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "getCipher", "()Ljavax/crypto/Cipher;", null, null).apply {
                    instructions.add(LdcInsnNode("AES/GCM/NoPadding"))
                    instructions.add(
                        MethodInsnNode(
                            Opcodes.INVOKESTATIC,
                            "javax/crypto/Cipher",
                            "getInstance",
                            "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                            false
                        )
                    )
                    instructions.add(InsnNode(Opcodes.ARETURN))
                }
            )
        }

        val collector = VaultCollector(testSeed())
        val changed = CallIndirectionPass.transform(cn, testConfig(), collector)
        assertTrue(changed)
        val insns = cn.methods[0].instructions
        assertFalse(insns.any { it is MethodInsnNode && it.owner == "javax/crypto/Cipher" })
        assertTrue(insns.any { it is InvokeDynamicInsnNode && it.bsm.name == "bootstrap" })
        assertEquals(1, collector.strings.size)
    }

    @Test
    fun `virtualization compiles method to shuffled VM bytecode`() {
        val cn = ClassNode().apply {
            version = Opcodes.V11
            access = Opcodes.ACC_PUBLIC
            name = "com/example/core/License"
            superName = "java/lang/Object"
            methods.add(
                MethodNode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "verify", "(II)I", null, null).apply {
                    invisibleAnnotations = mutableListOf(AnnotationNode(AnnotationHelper.ANN_VIRTUALIZE))
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 0))
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 1))
                    instructions.add(InsnNode(Opcodes.IXOR))
                    instructions.add(LdcInsnNode(0x5A5A))
                    instructions.add(InsnNode(Opcodes.IADD))
                    instructions.add(InsnNode(Opcodes.IRETURN))
                }
            )
        }

        val seed = testSeed()
        val collector = VaultCollector(seed)
        val changed = VirtualizationPass.transform(cn, testConfig(), seed, collector)
        assertTrue(changed)
        assertEquals(1, collector.vmPrograms.size)
        val prog = collector.vmPrograms[0]
        assertTrue(prog.bytecode.isNotEmpty())
        val verifyMethod = cn.methods[0]
        assertTrue(verifyMethod.instructions.any { it is MethodInsnNode && it.name == "executeInt" })
    }

    @Test
    fun `stripAnnotations removes Veil annotations and kotlin Metadata`() {
        val cn = ClassNode().apply {
            version = Opcodes.V11
            access = Opcodes.ACC_PUBLIC
            name = "com/example/core/Annotated"
            superName = "java/lang/Object"
            visibleAnnotations = mutableListOf(AnnotationNode(AnnotationHelper.ANN_KOTLIN_METADATA))
            invisibleAnnotations = mutableListOf(AnnotationNode(AnnotationHelper.ANN_OBFUSCATE))
        }
        AnnotationHelper.stripAnnotations(cn, stripVeil = true, stripKotlinMetadata = true, isProtectedClass = true)
        assertTrue(cn.visibleAnnotations.isNullOrEmpty())
        assertTrue(cn.invisibleAnnotations.isNullOrEmpty())
    }
}
