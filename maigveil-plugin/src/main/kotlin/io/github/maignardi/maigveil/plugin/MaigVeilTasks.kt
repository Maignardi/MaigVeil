package io.github.maignardi.maigveil.plugin

import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.Directory
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFile
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.tree.ClassNode
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream

@CacheableTask
abstract class GenerateMaigVeilSeedTask : DefaultTask() {

    @get:Input
    abstract val certBindingSpec: Property<String>

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val keystoreFile: RegularFileProperty

    @get:Input
    @get:Optional
    abstract val keystorePassword: Property<String>

    @get:Input
    @get:Optional
    abstract val keyAlias: Property<String>

    @get:Input
    @get:Optional
    abstract val storeType: Property<String>

    @get:OutputFile
    abstract val seedOutputFile: RegularFileProperty

    @TaskAction
    fun generate() {
        val certSha256 = resolveCertSha256()
        val seedData = BuildSeedData.generate(certSha256)
        seedData.writeTo(seedOutputFile.get().asFile)
        logger.lifecycle("[MaigVeil] Generated 256-bit BuildEntropySeed & polymorphic ARX/VM tables (cert=${certSha256.take(6).joinToString("") { "%02x".format(it) }}...).")
    }

    private fun resolveCertSha256(): ByteArray {
        val spec = certBindingSpec.get().trim()
        if (spec != "AUTO_EXTRACT_FROM_SIGNING_CONFIG" && spec.isNotEmpty()) {
            val clean = spec.replace(":", "").replace(" ", "")
            require(clean.length == 64) { "bindApkSigningCertSha256 must be 64 hex chars (SHA-256)" }
            return ByteArray(32) { i -> clean.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        }

        val ksFile = keystoreFile.orNull?.asFile
        if (ksFile != null && ksFile.exists()) {
            val ks = KeyStore.getInstance(storeType.orNull ?: KeyStore.getDefaultType())
            val pwd = (keystorePassword.orNull ?: "android").toCharArray()
            ksFile.inputStream().use { ks.load(it, pwd) }
            val alias = keyAlias.orNull ?: ks.aliases().asSequence().firstOrNull()
            if (alias != null) {
                val cert = ks.getCertificate(alias)
                if (cert != null) {
                    return MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                }
            }
        }
        return ByteArray(32)
    }
}

@CacheableTask
abstract class MaigVeilBytecodeTransformTask : DefaultTask() {

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val allJars: ListProperty<RegularFile>

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val allDirectories: ListProperty<Directory>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val seedFile: RegularFileProperty

    @get:Input
    abstract val config: Property<ResolvedMaigVeilConfig>

    @get:OutputFile
    abstract val outputJar: RegularFileProperty

    @get:OutputFile
    abstract val vaultOutputFile: RegularFileProperty

    @TaskAction
    fun transform() {
        val cfg = config.get()
        val seedData = BuildSeedData.readFrom(seedFile.get().asFile)
        val collector = VaultCollector(seedData)
        val rng = SecureRandom()

        val outFile = outputJar.get().asFile
        outFile.parentFile?.mkdirs()

        val seenEntries = HashSet<String>()
        var transformedClasses = 0
        var virtualizedMethods = 0

        JarOutputStream(BufferedOutputStream(FileOutputStream(outFile))).use { jos ->
            // Process input directories
            for (dir in allDirectories.get()) {
                val root = dir.asFile
                if (!root.exists()) continue
                root.walkTopDown().filter { it.isFile }.forEach { file ->
                    val rel = file.relativeTo(root).invariantSeparatorsPath
                    if (!seenEntries.add(rel)) return@forEach
                    val bytes = file.readBytes()
                    val result = if (cfg.enabled && rel.endsWith(".class")) {
                        val (outBytes, changed, vmCount) = processClass(bytes, cfg, seedData, collector, rng)
                        if (changed) transformedClasses++
                        virtualizedMethods += vmCount
                        outBytes
                    } else {
                        bytes
                    }
                    jos.putNextEntry(JarEntry(rel))
                    jos.write(result)
                    jos.closeEntry()
                }
            }

            // Process input jars
            for (jarReg in allJars.get()) {
                val jarFile = jarReg.asFile
                if (!jarFile.exists()) continue
                JarFile(jarFile).use { jf ->
                    val entries = jf.entries()
                    while (entries.hasMoreElements()) {
                        val entry = entries.nextElement()
                        if (entry.isDirectory || !seenEntries.add(entry.name)) continue
                        val bytes = jf.getInputStream(entry).use { it.readBytes() }
                        val result = if (cfg.enabled && entry.name.endsWith(".class")) {
                            val (outBytes, changed, vmCount) = processClass(bytes, cfg, seedData, collector, rng)
                            if (changed) transformedClasses++
                            virtualizedMethods += vmCount
                            outBytes
                        } else {
                            bytes
                        }
                        jos.putNextEntry(JarEntry(entry.name))
                        jos.write(result)
                        jos.closeEntry()
                    }
                }
            }
        }

        val flags = (if (cfg.zeroTraceMode) 0x02 else 0x00) or 0x01
        VaultWriter.writeVault(
            outFile = vaultOutputFile.get().asFile,
            seedData = seedData,
            strings = collector.strings,
            vmPrograms = collector.vmPrograms,
            flags = flags
        )

        logger.lifecycle(
            "[MaigVeil] Protected $transformedClasses classes | " +
                "${collector.strings.size} strings (ARX) | " +
                "${collector.vmPrograms.size} methods (C++20 VM) | " +
                "profile=${cfg.profile}"
        )
    }

    private data class ClassProcessResult(
        val bytes: ByteArray,
        val modified: Boolean,
        val vmCount: Int
    )

    private fun processClass(
        bytes: ByteArray,
        cfg: ResolvedMaigVeilConfig,
        seedData: BuildSeedData,
        collector: VaultCollector,
        rng: SecureRandom
    ): ClassProcessResult {
        val cn = ClassNode()
        ClassReader(bytes).accept(cn, ClassReader.EXPAND_FRAMES)

        val isProtected = cfg.isTargetClass(cn.name) || AnnotationHelper.hasVeilAnnotation(cn) ||
            cn.methods.any { AnnotationHelper.hasVeilAnnotation(it) }

        if (!isProtected || AnnotationHelper.isIgnored(cn)) {
            return ClassProcessResult(bytes, modified = false, vmCount = 0)
        }

        val beforeVm = collector.vmPrograms.size
        var modified = false

        // Pass 4: Virtualization (runs before ControlFlowPass so @VeilVirtualize methods are compiled clean)
        if (VirtualizationPass.transform(cn, cfg, seedData, collector)) {
            modified = true
        }
        val vmDelta = collector.vmPrograms.size - beforeVm

        // Pass 3: Call Indirection (INVOKEDYNAMIC)
        if (CallIndirectionPass.transform(cn, cfg, collector)) {
            modified = true
        }

        // Pass 1: Polymorphic String & Constant Encryption
        if (StringEncryptionPass.transform(cn, cfg, collector)) {
            modified = true
        }

        // Pass 2: Control Flow Flattening & Opaque Predicates
        if (ControlFlowPass.transform(cn, cfg, rng)) {
            modified = true
        }

        // Strip @Veil* annotations and @kotlin.Metadata from protected classes
        if (cfg.stripAnnotations || cfg.stripKotlinMetadata) {
            AnnotationHelper.stripAnnotations(
                cn = cn,
                stripVeil = cfg.stripAnnotations,
                stripKotlinMetadata = cfg.stripKotlinMetadata,
                isProtectedClass = isProtected
            )
            modified = true
        }

        if (!modified) {
            return ClassProcessResult(bytes, modified = false, vmCount = 0)
        }

        val cw = object : ClassWriter(ClassWriter.COMPUTE_FRAMES) {
            override fun getCommonSuperClass(type1: String, type2: String): String {
                return try {
                    super.getCommonSuperClass(type1, type2)
                } catch (_: Throwable) {
                    "java/lang/Object"
                }
            }
        }
        cn.accept(cw)
        return ClassProcessResult(cw.toByteArray(), modified = true, vmCount = vmDelta)
    }
}

@CacheableTask
abstract class AssetShieldTask : DefaultTask() {

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val inputAssetsDir: DirectoryProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val seedFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val vaultFile: RegularFileProperty

    @get:Input
    abstract val encryptPatterns: ListProperty<String>

    @get:OutputDirectory
    abstract val outputAssetsDir: DirectoryProperty

    @TaskAction
    fun shieldAssets() {
        val inRoot = inputAssetsDir.get().asFile
        val outRoot = outputAssetsDir.get().asFile
        outRoot.deleteRecursively()
        outRoot.mkdirs()

        val seedData = BuildSeedData.readFrom(seedFile.get().asFile)
        val patterns = encryptPatterns.get().map { globToRegex(it) }
        val rng = SecureRandom()
        var encryptedCount = 0

        if (inRoot.exists()) {
            inRoot.walkTopDown().filter { it.isFile }.forEach { src ->
                val rel = src.relativeTo(inRoot).invariantSeparatorsPath
                val dst = File(outRoot, rel)
                dst.parentFile?.mkdirs()

                if (patterns.any { it.matches(rel) }) {
                    val plain = src.readBytes()
                    val nonce = ByteArray(12).also { rng.nextBytes(it) }
                    val header = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).apply {
                        put("MVAS".toByteArray(Charsets.US_ASCII))
                        put(nonce)
                    }.array()

                    val assetKey = MaigVeilCrypto.hkdfSha256(
                        ikm = seedData.sessionKey,
                        salt = nonce,
                        info = "MaigVeil-Asset:$rel".toByteArray(Charsets.UTF_8)
                    )
                    val (cipher, tag) = MaigVeilCrypto.chacha20Poly1305Encrypt(
                        key = assetKey,
                        nonce = nonce,
                        aad = header,
                        plaintext = plain
                    )
                    dst.outputStream().buffered().use { out ->
                        out.write(header)
                        out.write(cipher)
                        out.write(tag)
                    }
                    encryptedCount++
                } else {
                    src.copyTo(dst, overwrite = true)
                }
            }
        }

        // Embed encrypted mv_vault.bin into assets root
        vaultFile.get().asFile.copyTo(File(outRoot, "mv_vault.bin"), overwrite = true)
        logger.lifecycle("[MaigVeil] AssetShield encrypted $encryptedCount assets (ChaCha20-Poly1305) & packaged mv_vault.bin.")
    }

    private fun globToRegex(glob: String): Regex {
        val sb = StringBuilder("^")
        for (ch in glob) {
            when (ch) {
                '*' -> sb.append(".*")
                '?' -> sb.append('.')
                '.' -> sb.append("\\.")
                '/' -> sb.append('/')
                else -> sb.append(Regex.escape(ch.toString()))
            }
        }
        sb.append("$")
        return Regex(sb.toString())
    }
}
