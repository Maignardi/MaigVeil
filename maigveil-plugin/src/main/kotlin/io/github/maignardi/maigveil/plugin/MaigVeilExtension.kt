package io.github.maignardi.maigveil.plugin

import org.gradle.api.Action
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Nested
import java.io.Serializable
import javax.inject.Inject

enum class VeilProfile {
    LIGHT,
    BALANCED,
    PARANOID
}

abstract class StringObfuscationConfig @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val encryptConstVals: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val zeroTraceMode: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
}

abstract class ControlFlowConfig @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val flatteningProbability: Property<Int> = objects.property(Int::class.java).convention(80)
    val opaquePredicatesLevel: Property<Int> = objects.property(Int::class.java).convention(2)
}

abstract class CallIndirectionConfig @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val targetApis: ListProperty<String> = objects.listProperty(String::class.java).convention(
        listOf("javax/crypto/*", "okhttp3/*", "java/security/*", "android/telephony/*")
    )
}

abstract class VirtualizationConfig @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
}

abstract class AssetsConfig @Inject constructor(objects: ObjectFactory) {
    val encryptFiles: ListProperty<String> = objects.listProperty(String::class.java).convention(emptyList())
}

abstract class AntiTamperConfig @Inject constructor(objects: ObjectFactory) {
    val bindApkSigningCertSha256: Property<String> = objects.property(String::class.java)
        .convention("AUTO_EXTRACT_FROM_SIGNING_CONFIG")
    val stripKotlinMetadata: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val stripAnnotations: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
}

abstract class MaigVeilExtension @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val profile: Property<VeilProfile> = objects.property(VeilProfile::class.java).convention(VeilProfile.BALANCED)
    val targetPackages: ListProperty<String> = objects.listProperty(String::class.java).convention(emptyList())
    val excludePackages: ListProperty<String> = objects.listProperty(String::class.java).convention(emptyList())

    @get:Nested
    val stringObfuscation: StringObfuscationConfig = objects.newInstance(StringObfuscationConfig::class.java)

    @get:Nested
    val controlFlow: ControlFlowConfig = objects.newInstance(ControlFlowConfig::class.java)

    @get:Nested
    val callIndirection: CallIndirectionConfig = objects.newInstance(CallIndirectionConfig::class.java)

    @get:Nested
    val virtualization: VirtualizationConfig = objects.newInstance(VirtualizationConfig::class.java)

    @get:Nested
    val assets: AssetsConfig = objects.newInstance(AssetsConfig::class.java)

    @get:Nested
    val antiTamper: AntiTamperConfig = objects.newInstance(AntiTamperConfig::class.java)

    fun stringObfuscation(action: Action<StringObfuscationConfig>) = action.execute(stringObfuscation)
    fun controlFlow(action: Action<ControlFlowConfig>) = action.execute(controlFlow)
    fun callIndirection(action: Action<CallIndirectionConfig>) = action.execute(callIndirection)
    fun virtualization(action: Action<VirtualizationConfig>) = action.execute(virtualization)
    fun assets(action: Action<AssetsConfig>) = action.execute(assets)
    fun antiTamper(action: Action<AntiTamperConfig>) = action.execute(antiTamper)
}

/**
 * Immutable, Configuration-Cache-safe snapshot of [MaigVeilExtension].
 */
data class ResolvedMaigVeilConfig(
    val enabled: Boolean,
    val profile: VeilProfile,
    val targetPackages: List<String>,
    val excludePackages: List<String>,
    val stringEnabled: Boolean,
    val encryptConstVals: Boolean,
    val zeroTraceMode: Boolean,
    val controlFlowEnabled: Boolean,
    val flatteningProbability: Int,
    val opaquePredicatesLevel: Int,
    val callIndirectionEnabled: Boolean,
    val targetApis: List<String>,
    val virtualizationEnabled: Boolean,
    val encryptAssets: List<String>,
    val bindApkSigningCertSha256: String,
    val stripKotlinMetadata: Boolean,
    val stripAnnotations: Boolean
) : Serializable {

    fun isTargetClass(internalName: String): Boolean {
        if (internalName.startsWith("io/github/maignardi/maigveil/runtime/") ||
            internalName.startsWith("io/github/maignardi/maigveil/annotations/")
        ) {
            return false
        }
        val dotName = internalName.replace('/', '.')
        if (excludePackages.any { prefix -> dotName.startsWith(prefix) }) {
            return false
        }
        if (targetPackages.isEmpty()) return true
        return targetPackages.any { prefix -> dotName.startsWith(prefix) }
    }

    companion object {
        fun from(ext: MaigVeilExtension): ResolvedMaigVeilConfig {
            val prof = ext.profile.get()
            val defaultFlat = when (prof) {
                VeilProfile.LIGHT -> 0
                VeilProfile.BALANCED -> 60
                VeilProfile.PARANOID -> 90
            }
            val defaultOpaque = when (prof) {
                VeilProfile.LIGHT -> 0
                VeilProfile.BALANCED -> 1
                VeilProfile.PARANOID -> 2
            }
            return ResolvedMaigVeilConfig(
                enabled = ext.enabled.get(),
                profile = prof,
                targetPackages = ext.targetPackages.get(),
                excludePackages = ext.excludePackages.get(),
                stringEnabled = ext.stringObfuscation.enabled.get(),
                encryptConstVals = ext.stringObfuscation.encryptConstVals.get(),
                zeroTraceMode = ext.stringObfuscation.zeroTraceMode.get(),
                controlFlowEnabled = ext.controlFlow.enabled.get() && (prof != VeilProfile.LIGHT || ext.controlFlow.flatteningProbability.isPresent),
                flatteningProbability = if (ext.controlFlow.flatteningProbability.isPresent) ext.controlFlow.flatteningProbability.get() else defaultFlat,
                opaquePredicatesLevel = if (ext.controlFlow.opaquePredicatesLevel.isPresent) ext.controlFlow.opaquePredicatesLevel.get() else defaultOpaque,
                callIndirectionEnabled = ext.callIndirection.enabled.get(),
                targetApis = ext.callIndirection.targetApis.get(),
                virtualizationEnabled = ext.virtualization.enabled.get(),
                encryptAssets = ext.assets.encryptFiles.get(),
                bindApkSigningCertSha256 = ext.antiTamper.bindApkSigningCertSha256.get(),
                stripKotlinMetadata = ext.antiTamper.stripKotlinMetadata.get(),
                stripAnnotations = ext.antiTamper.stripAnnotations.get()
            )
        }
    }
}
