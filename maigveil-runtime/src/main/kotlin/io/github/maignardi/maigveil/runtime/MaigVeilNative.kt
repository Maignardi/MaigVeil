package io.github.maignardi.maigveil.runtime

import java.nio.ByteBuffer

/**
 * Low-level JNI bridge whose methods are registered dynamically via `RegisterNatives`
 * inside `JNI_OnLoad` with zero exported `Java_*` symbols.
 */
internal object MaigVeilNative {
    init {
        System.loadLibrary("maigveil")
    }

    @JvmStatic external fun nativeInit(assetManager: Any): Boolean
    @JvmStatic external fun nativeDecryptString(stringId: Int): String
    @JvmStatic external fun nativeAllocZeroTrace(stringId: Int): LongArray
    @JvmStatic external fun nativeWrapDirectBuffer(addr: Long, len: Long): ByteBuffer?
    @JvmStatic external fun nativeReleaseZeroTrace(addr: Long, len: Long)
    @JvmStatic external fun nativeDecryptAsset(assetPath: String, encryptedBytes: ByteArray): ByteArray?
    @JvmStatic external fun nativeExecVmInt(programId: Int, args: Array<Any?>?): Int
    @JvmStatic external fun nativeExecVmLong(programId: Int, args: Array<Any?>?): Long
    @JvmStatic external fun nativeExecVmObj(programId: Int, args: Array<Any?>?): Any?
    @JvmStatic external fun nativeExecVmVoid(programId: Int, args: Array<Any?>?)
    @JvmStatic external fun nativeGetStatus(): IntArray
}
