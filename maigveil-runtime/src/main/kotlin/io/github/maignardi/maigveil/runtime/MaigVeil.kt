package io.github.maignardi.maigveil.runtime

import android.content.Context
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets

/**
 * Snapshot of the native runtime security and integrity state.
 */
data class MaigVeilStatus(
    val initialized: Boolean,
    val vaultAuthenticated: Boolean,
    val textIntegrityOk: Boolean,
    val noInlineHooks: Boolean,
    val noDebuggerAttached: Boolean,
    val protectedStringCount: Int,
    val virtualizedMethodCount: Int
) {
    val isHealthy: Boolean
        get() = initialized && vaultAuthenticated && textIntegrityOk && noInlineHooks && noDebuggerAttached
}

/**
 * Primary runtime entry point for MaigVeil's native security engine.
 */
object MaigVeil {

    @Volatile
    private var initialized = false

    /**
     * Initializes the native MaigVeil engine and authenticates `mv_vault.bin`
     * against the APK's v2/v3 signing certificate SHA-256.
     */
    @JvmStatic
    fun init(context: Context): Boolean {
        if (initialized) return true
        synchronized(this) {
            if (initialized) return true
            val ok = MaigVeilNative.nativeInit(context.applicationContext.assets)
            initialized = true
            return ok
        }
    }

    /**
     * Decrypts a protected string literal by its vault ID.
     * Invoked by bytecode rewritten during Pass 1 (`StringEncryptionPass`).
     */
    @JvmStatic
    fun decryptString(stringId: Int): String {
        return MaigVeilNative.nativeDecryptString(stringId)
    }

    /**
     * Zero-Trace secret accessor.
     *
     * Decodes the secret directly into `mmap` + `mlock` native memory, exposes it as a
     * transient [CharBuffer] backed by a wiped array, and immediately zeroes + unlocks + unmaps
     * the native pages when [block] returns or throws.
     */
    @JvmStatic
    inline fun <T> withSecret(stringId: Int, block: (CharBuffer) -> T): T {
        val handle = allocZeroTraceHandle(stringId)
        val addr = handle[0]
        val len = handle[1]
        val directBuf = wrapZeroTraceBuffer(addr, len)
        val chars = if (directBuf != null && len > 0) {
            val bytes = ByteArray(len.toInt())
            directBuf.get(bytes)
            val decoded = StandardCharsets.UTF_8.decode(java.nio.ByteBuffer.wrap(bytes))
            bytes.fill(0)
            decoded
        } else {
            CharBuffer.allocate(0)
        }
        return try {
            block(chars)
        } finally {
            if (chars.hasArray()) {
                chars.array().fill('\u0000')
            }
            releaseZeroTraceHandle(addr, len)
        }
    }

    /**
     * Ergonomic Zero-Trace secret accessor.
     *
     * When compiled with the MaigVeil Gradle plugin, `StringEncryptionPass` rewrites
     * `LDC <literal>` + `withZeroTraceSecret` directly to `withSecretId(stringId, block)`,
     * ensuring the secret literal is removed from DEX and never allocated as a `java.lang.String`.
     */
    @JvmStatic
    fun <T> withZeroTraceSecret(secret: String, block: (CharBuffer) -> T): T {
        val arr = secret.toCharArray()
        val buf = CharBuffer.wrap(arr)
        return try {
            block(buf)
        } finally {
            arr.fill('\u0000')
        }
    }

    /**
     * Intrinsic target for [withZeroTraceSecret] after `StringEncryptionPass` rewriting.
     */
    @JvmStatic
    fun <T> withSecretId(stringId: Int, block: (CharBuffer) -> T): T {
        return withSecret(stringId) { buf -> block(buf) }
    }

    @PublishedApi
    internal fun allocZeroTraceHandle(stringId: Int): LongArray =
        MaigVeilNative.nativeAllocZeroTrace(stringId)

    @PublishedApi
    internal fun wrapZeroTraceBuffer(addr: Long, len: Long) =
        MaigVeilNative.nativeWrapDirectBuffer(addr, len)

    @PublishedApi
    internal fun releaseZeroTraceHandle(addr: Long, len: Long) {
        MaigVeilNative.nativeReleaseZeroTrace(addr, len)
    }

    /**
     * Returns live diagnostics from the native self-defense engine.
     */
    @JvmStatic
    fun status(): MaigVeilStatus {
        val raw = MaigVeilNative.nativeGetStatus()
        return MaigVeilStatus(
            initialized = raw.getOrElse(0) { 0 } == 1,
            vaultAuthenticated = raw.getOrElse(1) { 0 } == 1,
            textIntegrityOk = raw.getOrElse(2) { 0 } == 1,
            noInlineHooks = raw.getOrElse(3) { 0 } == 1,
            noDebuggerAttached = raw.getOrElse(4) { 0 } == 1,
            protectedStringCount = raw.getOrElse(5) { 0 },
            virtualizedMethodCount = raw.getOrElse(6) { 0 }
        )
    }
}
