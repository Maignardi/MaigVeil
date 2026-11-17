package io.github.maignardi.maigveil.plugin

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AnnotationNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TryCatchBlockNode
import org.objectweb.asm.tree.VarInsnNode
import java.io.File
import java.security.SecureRandom

class MaigVeilSecuritySuiteTest {

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "").replace(":", "")
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    @Test
    fun `RFC 8439 ChaCha20-Poly1305 test vector matches specification`() {
        // IETF RFC 8439 Section 2.8.2 AEAD test vector
        val key = hexToBytes(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        )
        val nonce = hexToBytes("070000004041424344454647")
        val aad = hexToBytes("50515253c0c1c2c3c4c5c6c7")
        val plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
            .toByteArray(Charsets.US_ASCII)

        val expectedCipher = hexToBytes(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b6116"
        )
        val expectedTag = hexToBytes("1ae10b594f09e26a7e902ecbd0600691")

        val (cipher, tag) = MaigVeilCrypto.chacha20Poly1305Encrypt(key, nonce, aad, plaintext)
        assertArrayEquals(expectedCipher, cipher)
        assertArrayEquals(expectedTag, tag)
    }

    @Test
    fun `repackaged APK certificate yields different session key`() {
        val originalCert = ByteArray(32) { (it + 1).toByte() }
        val attackerCert = ByteArray(32) { (it + 2).toByte() }
        val seed = ByteArray(32) { (it * 7).toByte() }

        val originalKey = MaigVeilCrypto.deriveSessionKey(originalCert, seed)
        val attackerKey = MaigVeilCrypto.deriveSessionKey(attackerCert, seed)

        assertFalse(originalKey.contentEquals(attackerKey))
    }

    @Test
    fun `polymorphic builds produce distinct seeds schedules opcodes and ciphertexts`() {
        val cert = ByteArray(32) { 0x42 }
        val seedA = BuildSeedData.generate(cert, SecureRandom())
        val seedB = BuildSeedData.generate(cert, SecureRandom())

        assertFalse(seedA.buildEntropySeed.contentEquals(seedB.buildEntropySeed))
        assertFalse(seedA.arxSchedule.contentEquals(seedB.arxSchedule))
        assertFalse(seedA.opcodeEncodeTable.contentEquals(seedB.opcodeEncodeTable))

        val plain = "TopSecretApiKey_2026".toByteArray()
        val cA = MaigVeilCrypto.arxEncrypt(seedA.sessionKey, seedA.arxSchedule, 1, 2, 3, plain)
        val cB = MaigVeilCrypto.arxEncrypt(seedB.sessionKey, seedB.arxSchedule, 1, 2, 3, plain)
        assertFalse(cA.contentEquals(cB))
        assertFalse(cA.contentEquals(plain))
    }

    @Test
    fun `control flow flattening handles loops and preserves exact semantics`() {
        // int sumLoop(int n) { int s = 0; for (int i = 0; i < n; i++) { s += i * 3; } return s; }
        val cn = ClassNode().apply {
            version = Opcodes.V11
            access = Opcodes.ACC_PUBLIC
            name = "com/example/core/LoopStress"
            superName = "java/lang/Object"
            methods.add(
                MethodNode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "sumLoop", "(I)I", null, null).apply {
                    val loopHead = LabelNode()
                    val loopEnd = LabelNode()
                    // s = 0 (local 1), i = 0 (local 2)
                    instructions.add(InsnNode(Opcodes.ICONST_0))
                    instructions.add(VarInsnNode(Opcodes.ISTORE, 1))
                    instructions.add(InsnNode(Opcodes.ICONST_0))
                    instructions.add(VarInsnNode(Opcodes.ISTORE, 2))
                    instructions.add(loopHead)
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 2))
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 0))
                    instructions.add(JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd))
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 1))
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 2))
                    instructions.add(InsnNode(Opcodes.ICONST_3))
                    instructions.add(InsnNode(Opcodes.IMUL))
                    instructions.add(InsnNode(Opcodes.IADD))
                    instructions.add(VarInsnNode(Opcodes.ISTORE, 1))
                    instructions.add(org.objectweb.asm.tree.IincInsnNode(2, 1))
                    instructions.add(JumpInsnNode(Opcodes.GOTO, loopHead))
                    instructions.add(loopEnd)
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 1))
                    instructions.add(InsnNode(Opcodes.IRETURN))
                }
            )
        }

        val cfg = ResolvedMaigVeilConfig(
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
            callIndirectionEnabled = false,
            targetApis = emptyList(),
            virtualizationEnabled = false,
            encryptAssets = emptyList(),
            bindApkSigningCertSha256 = "",
            stripKotlinMetadata = true,
            stripAnnotations = true
        )

        assertTrue(ControlFlowPass.transform(cn, cfg, SecureRandom()))

        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        cn.accept(cw)
        val bytes = cw.toByteArray()
        ClassReader(bytes)

        val loader = object : ClassLoader(this::class.java.classLoader) {
            fun define(name: String, b: ByteArray): Class<*> = defineClass(name, b, 0, b.size)
        }
        val cls = loader.define("com.example.core.LoopStress", bytes)
        val m = cls.getMethod("sumLoop", Int::class.javaPrimitiveType)
        assertEquals(0, m.invoke(null, 0))
        assertEquals(30, m.invoke(null, 5)) // (0+1+2+3+4)*3 = 30
        assertEquals(135, m.invoke(null, 10)) // 45*3 = 135
    }

    @Test
    fun `control flow pass safely skips try-catch methods without corrupting frames`() {
        val cn = ClassNode().apply {
            version = Opcodes.V11
            access = Opcodes.ACC_PUBLIC
            name = "com/example/core/TryCatchMethod"
            superName = "java/lang/Object"
            methods.add(
                MethodNode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "safe", "()I", null, null).apply {
                    val l0 = LabelNode()
                    val l1 = LabelNode()
                    val l2 = LabelNode()
                    tryCatchBlocks.add(TryCatchBlockNode(l0, l1, l2, "java/lang/Exception"))
                    instructions.add(l0)
                    instructions.add(InsnNode(Opcodes.ICONST_1))
                    instructions.add(l1)
                    instructions.add(InsnNode(Opcodes.IRETURN))
                    instructions.add(l2)
                    instructions.add(InsnNode(Opcodes.POP))
                    instructions.add(InsnNode(Opcodes.ICONST_0))
                    instructions.add(InsnNode(Opcodes.IRETURN))
                }
            )
        }
        val cfg = ResolvedMaigVeilConfig(
            enabled = true,
            profile = VeilProfile.PARANOID,
            targetPackages = listOf("com.example.core"),
            excludePackages = emptyList(),
            stringEnabled = false,
            encryptConstVals = false,
            zeroTraceMode = false,
            controlFlowEnabled = true,
            flatteningProbability = 100,
            opaquePredicatesLevel = 2,
            callIndirectionEnabled = false,
            targetApis = emptyList(),
            virtualizationEnabled = false,
            encryptAssets = emptyList(),
            bindApkSigningCertSha256 = "",
            stripKotlinMetadata = false,
            stripAnnotations = false
        )
        assertFalse(ControlFlowPass.transform(cn, cfg, SecureRandom()))
    }

    @Test
    fun `virtualization compiles array and long bitwise logic into shuffled VM bytecode`() {
        val cn = ClassNode().apply {
            version = Opcodes.V11
            access = Opcodes.ACC_PUBLIC
            name = "com/example/core/VmStress"
            superName = "java/lang/Object"
            methods.add(
                MethodNode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "mixLong", "(JI)J", null, null).apply {
                    invisibleAnnotations = mutableListOf(AnnotationNode(AnnotationHelper.ANN_VIRTUALIZE))
                    instructions.add(VarInsnNode(Opcodes.LLOAD, 0))
                    instructions.add(VarInsnNode(Opcodes.ILOAD, 2))
                    instructions.add(InsnNode(Opcodes.I2L))
                    instructions.add(InsnNode(Opcodes.LXOR))
                    instructions.add(IntInsnNode(Opcodes.BIPUSH, 7))
                    instructions.add(InsnNode(Opcodes.LSHL))
                    instructions.add(InsnNode(Opcodes.LRETURN))
                }
            )
        }

        val seed = BuildSeedData.generate(ByteArray(32) { 1 })
        val collector = VaultCollector(seed)
        val cfg = ResolvedMaigVeilConfig(
            enabled = true,
            profile = VeilProfile.PARANOID,
            targetPackages = listOf("com.example.core"),
            excludePackages = emptyList(),
            stringEnabled = false,
            encryptConstVals = false,
            zeroTraceMode = false,
            controlFlowEnabled = false,
            flatteningProbability = 0,
            opaquePredicatesLevel = 0,
            callIndirectionEnabled = false,
            targetApis = emptyList(),
            virtualizationEnabled = true,
            encryptAssets = emptyList(),
            bindApkSigningCertSha256 = "",
            stripKotlinMetadata = false,
            stripAnnotations = false
        )

        assertTrue(VirtualizationPass.transform(cn, cfg, seed, collector))
        assertEquals(1, collector.vmPrograms.size)
        val prog = collector.vmPrograms[0]
        assertEquals(2, prog.paramCount) // (J, I) -> 2 VM param slots
        assertEquals(2, prog.returnType) // LONG
        assertTrue(cn.methods[0].instructions.any { it is MethodInsnNode && it.name == "executeLong" })
    }

    @Test
    fun `excluded packages and VeilIgnore classes are never modified`() {
        val cfg = ResolvedMaigVeilConfig(
            enabled = true,
            profile = VeilProfile.PARANOID,
            targetPackages = listOf("com.example.core"),
            excludePackages = listOf("com.example.core.ui"),
            stringEnabled = true,
            encryptConstVals = true,
            zeroTraceMode = true,
            controlFlowEnabled = true,
            flatteningProbability = 100,
            opaquePredicatesLevel = 2,
            callIndirectionEnabled = true,
            targetApis = listOf("javax/crypto/*"),
            virtualizationEnabled = true,
            encryptAssets = emptyList(),
            bindApkSigningCertSha256 = "",
            stripKotlinMetadata = true,
            stripAnnotations = true
        )

        assertFalse(cfg.isTargetClass("com/example/core/ui/Theme"))
        assertTrue(cfg.isTargetClass("com/example/core/Vault"))

        val ignoredCn = ClassNode().apply {
            version = Opcodes.V11
            access = Opcodes.ACC_PUBLIC
            name = "com/example/core/Ignored"
            superName = "java/lang/Object"
            invisibleAnnotations = mutableListOf(AnnotationNode(AnnotationHelper.ANN_IGNORE))
            methods.add(
                MethodNode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "s", "()Ljava/lang/String;", null, null).apply {
                    instructions.add(LdcInsnNode("keep_me"))
                    instructions.add(InsnNode(Opcodes.ARETURN))
                }
            )
        }
        val collector = VaultCollector(BuildSeedData.generate(ByteArray(32)))
        assertFalse(StringEncryptionPass.transform(ignoredCn, cfg, collector))
        assertEquals(0, collector.strings.size)
    }

    @Test
    fun `vault writer produces authenticated binary vault`() {
        val seed = BuildSeedData.generate(ByteArray(32) { 0x11 })
        val tmp = File.createTempFile("mv_vault_test", ".bin").apply { deleteOnExit() }
        VaultWriter.writeVault(tmp, seed, emptyList(), emptyList(), flags = 3)
        val bytes = tmp.readBytes()
        assertTrue(bytes.size >= 48 + 8 + 256 + 16)
        assertEquals("MVLT", String(bytes.copyOfRange(0, 4), Charsets.US_ASCII))
    }
}
