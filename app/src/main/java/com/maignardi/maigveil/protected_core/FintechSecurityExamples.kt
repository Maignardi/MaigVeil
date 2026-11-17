package com.maignardi.maigveil.protected_core

import android.content.Context
import io.github.maignardi.maigveil.annotations.VeilControlFlow
import io.github.maignardi.maigveil.annotations.VeilObfuscate
import io.github.maignardi.maigveil.annotations.VeilProfileLevel
import io.github.maignardi.maigveil.annotations.VeilString
import io.github.maignardi.maigveil.annotations.VeilVirtualize
import io.github.maignardi.maigveil.runtime.MaigVeil
import io.github.maignardi.maigveil.runtime.MaigVeilAssets

/**
 * Real-world mobile usage examples for MaigVeil.
 * Copy and adapt these patterns into your Android app's core/security package.
 */
@VeilObfuscate(profile = VeilProfileLevel.PARANOID)
@VeilString(zeroTrace = true)
object FintechSecurityExamples {

    /**
     * Example 1: Zero-Trace API Token Usage.
     * The string literal is stripped at compile time and decrypted directly into
     * `mmap` + `mlock` native pages, never allocated as a `java.lang.String`.
     */
    @JvmStatic
    fun signRequestWithZeroTraceToken(payload: String): String {
        return MaigVeil.withZeroTraceSecret("Bearer mv_live_ephemeral_signing_secret") { secretChars ->
            var hash = 0x811C9DC5.toInt()
            for (i in 0 until secretChars.length) {
                hash = (hash xor secretChars[i].code) * 0x01000193
            }
            for (ch in payload) {
                hash = (hash xor ch.code) * 0x01000193
            }
            "sig_${Integer.toHexString(hash)}"
        }
    }

    /**
     * Example 2: Offline Entitlement / License Verification inside C++20 VM.
     * The JVM body is completely replaced by `MaigVeilVM.executeInt(...)`.
     */
    @VeilVirtualize
    @JvmStatic
    fun isPremiumEntitlementValid(accountId: Int, entitlementCode: Int): Int {
        val expected = ((accountId xor 0x2026CAFE) + 7919) and 0x7FFFFFFF
        return if (entitlementCode == expected) 1 else 0
    }

    /**
     * Example 3: Anti-Fraud Transaction Gate with Flattened Control Flow.
     */
    @VeilControlFlow(flatteningProbability = 100, opaquePredicatesLevel = 2)
    @JvmStatic
    fun isTransactionAllowed(amountCents: Int, riskScore: Int): Boolean {
        if (riskScore >= 85) return false
        if (amountCents > 500_000 && riskScore > 40) return false
        return amountCents > 0
    }

    /**
     * Example 4: Loading ChaCha20-Poly1305 Encrypted Config/Cert Assets.
     */
    @JvmStatic
    fun loadPinnedCertificateHeader(context: Context): String {
        return MaigVeilAssets.open(context, "certs/pinned_root.pem")
            .bufferedReader()
            .use { it.readLine() ?: "" }
    }
}
