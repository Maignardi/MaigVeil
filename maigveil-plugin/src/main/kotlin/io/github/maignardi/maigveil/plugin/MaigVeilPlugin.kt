package io.github.maignardi.maigveil.plugin

import com.android.build.api.artifact.ScopedArtifact
import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.AndroidComponentsExtension
import com.android.build.api.variant.ScopedArtifacts
import org.gradle.api.Plugin
import org.gradle.api.Project
import java.io.File

/**
 * MaigVeil Gradle Plugin (`io.github.maignardi.maigveil`).
 *
 * Hooks into AGP's `AndroidComponentsExtension` and `variant.artifacts` to execute:
 * 1. `GenerateMaigVeilSeedTask` — Per-build 256-bit entropy seed & APK cert binding.
 * 2. `MaigVeilBytecodeTransformTask` — Multi-pass ASM 9 transformer (Strings, CFF, INVOKEDYNAMIC, VM).
 * 3. `AssetShieldTask` — ChaCha20-Poly1305 asset encryption & `mv_vault.bin` packaging.
 */
class MaigVeilPlugin : Plugin<Project> {

    override fun apply(project: Project) {
        val extension = project.extensions.create("maigVeil", MaigVeilExtension::class.java)

        val androidComponents = project.extensions.findByType(AndroidComponentsExtension::class.java)
            ?: return

        androidComponents.onVariants { variant ->
            val configProvider = project.provider { ResolvedMaigVeilConfig.from(extension) }
            val variantCap = variant.name.replaceFirstChar { it.uppercaseChar() }
            val buildDir = project.layout.buildDirectory

            val seedTask = project.tasks.register(
                "generateMaigVeilSeed$variantCap",
                GenerateMaigVeilSeedTask::class.java
            ) {
                certBindingSpec.set(extension.antiTamper.bindApkSigningCertSha256)
                seedOutputFile.set(buildDir.file("intermediates/maigveil/${variant.name}/seed.bin"))

                // Auto-extract keystore from AGP signing config (or fallback to debug.keystore)
                val androidExt = project.extensions.findByName("android")
                val signingCfg = runCatching {
                    val buildTypes = androidExt?.javaClass?.getMethod("getBuildTypes")?.invoke(androidExt)
                    val bt = buildTypes?.javaClass?.getMethod("findByName", String::class.java)
                        ?.invoke(buildTypes, variant.buildType ?: "debug")
                    bt?.javaClass?.getMethod("getSigningConfig")?.invoke(bt)
                }.getOrNull()

                val ksFile = runCatching {
                    signingCfg?.javaClass?.getMethod("getStoreFile")?.invoke(signingCfg) as? File
                }.getOrNull() ?: File(System.getProperty("user.home"), ".android/debug.keystore")

                if (ksFile.exists()) {
                    keystoreFile.set(ksFile)
                    val storePwd = runCatching {
                        signingCfg?.javaClass?.getMethod("getStorePassword")?.invoke(signingCfg) as? String
                    }.getOrNull() ?: "android"
                    val alias = runCatching {
                        signingCfg?.javaClass?.getMethod("getKeyAlias")?.invoke(signingCfg) as? String
                    }.getOrNull() ?: "androiddebugkey"
                    val sType = runCatching {
                        signingCfg?.javaClass?.getMethod("getStoreType")?.invoke(signingCfg) as? String
                    }.getOrNull() ?: "PKCS12"
                    keystorePassword.set(storePwd)
                    keyAlias.set(alias)
                    storeType.set(sType)
                }
            }

            val transformTask = project.tasks.register(
                "maigVeilTransform$variantCap",
                MaigVeilBytecodeTransformTask::class.java
            ) {
                seedFile.set(seedTask.flatMap { it.seedOutputFile })
                config.set(configProvider)
                vaultOutputFile.set(buildDir.file("intermediates/maigveil/${variant.name}/mv_vault.bin"))
            }

            variant.artifacts
                .forScope(ScopedArtifacts.Scope.PROJECT)
                .use(transformTask)
                .toTransform(
                    ScopedArtifact.CLASSES,
                    MaigVeilBytecodeTransformTask::allJars,
                    MaigVeilBytecodeTransformTask::allDirectories,
                    MaigVeilBytecodeTransformTask::outputJar
                )

            val assetShieldTask = project.tasks.register(
                "maigVeilShieldAssets$variantCap",
                AssetShieldTask::class.java
            ) {
                seedFile.set(seedTask.flatMap { it.seedOutputFile })
                vaultFile.set(transformTask.flatMap { it.vaultOutputFile })
                encryptPatterns.set(extension.assets.encryptFiles)
            }

            variant.artifacts
                .use(assetShieldTask)
                .wiredWithDirectories(
                    AssetShieldTask::inputAssetsDir,
                    AssetShieldTask::outputAssetsDir
                )
                .toTransform(SingleArtifact.ASSETS)
        }
    }
}
