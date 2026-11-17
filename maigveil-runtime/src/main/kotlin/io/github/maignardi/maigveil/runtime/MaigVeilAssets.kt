package io.github.maignardi.maigveil.runtime

import android.content.Context
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream

/**
 * Transparent reader for assets encrypted at build time with ChaCha20-Poly1305
 * by `AssetShieldTask`.
 */
object MaigVeilAssets {

    /**
     * Opens an encrypted asset at [assetPath] and returns a decrypted [InputStream].
     * If the asset is not encrypted (no `MVAS` header), falls back to the raw asset stream.
     */
    @JvmStatic
    @Throws(IOException::class)
    fun open(context: Context, assetPath: String): InputStream {
        return ByteArrayInputStream(readBytes(context, assetPath))
    }

    /**
     * Reads and decrypts an encrypted asset at [assetPath].
     */
    @JvmStatic
    @Throws(IOException::class)
    fun readBytes(context: Context, assetPath: String): ByteArray {
        MaigVeil.init(context)
        val raw = context.assets.open(assetPath).use { it.readBytes() }
        if (raw.size >= 4 &&
            raw[0] == 'M'.code.toByte() &&
            raw[1] == 'V'.code.toByte() &&
            raw[2] == 'A'.code.toByte() &&
            raw[3] == 'S'.code.toByte()
        ) {
            return MaigVeilNative.nativeDecryptAsset(assetPath, raw)
                ?: throw IOException("Failed to authenticate encrypted asset: $assetPath")
        }
        return raw
    }
}
