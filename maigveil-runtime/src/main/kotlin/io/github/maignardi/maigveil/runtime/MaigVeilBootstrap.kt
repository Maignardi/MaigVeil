package io.github.maignardi.maigveil.runtime

import java.lang.invoke.CallSite
import java.lang.invoke.ConstantCallSite
import java.lang.invoke.MethodHandles
import java.lang.invoke.MethodType

/**
 * `INVOKEDYNAMIC` bootstrap resolver for `CallIndirectionPass`.
 *
 * Decrypts the target `"owner|methodName|descriptor|mode"` signature at runtime using
 * the native ARX engine and binds a [ConstantCallSite] to the resolved [java.lang.invoke.MethodHandle],
 * eliminating static call-graph edges in JADX/Ghidra.
 */
object MaigVeilBootstrap {

    @JvmStatic
    fun bootstrap(
        lookup: MethodHandles.Lookup,
        invokedName: String,
        invokedType: MethodType,
        encryptedTargetId: Int
    ): CallSite {
        val spec = MaigVeil.decryptString(encryptedTargetId)
        val parts = spec.split('|')
        require(parts.size == 4) { "Corrupted MaigVeil call-site descriptor" }

        val ownerInternal = parts[0].replace('/', '.')
        val methodName = parts[1]
        val methodDesc = parts[2]
        val isStatic = parts[3] == "S"

        val classLoader = lookup.lookupClass().classLoader ?: MaigVeilBootstrap::class.java.classLoader
        val ownerClass = Class.forName(ownerInternal, true, classLoader)
        val targetType = MethodType.fromMethodDescriptorString(methodDesc, classLoader)

        val handle = if (isStatic) {
            lookup.findStatic(ownerClass, methodName, targetType)
        } else {
            lookup.findVirtual(ownerClass, methodName, targetType)
        }

        return ConstantCallSite(handle.asType(invokedType))
    }
}
