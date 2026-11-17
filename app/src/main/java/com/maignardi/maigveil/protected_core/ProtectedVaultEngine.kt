package com.maignardi.maigveil.protected_core

import io.github.maignardi.maigveil.annotations.VeilControlFlow
import io.github.maignardi.maigveil.annotations.VeilIgnore
import io.github.maignardi.maigveil.annotations.VeilObfuscate
import io.github.maignardi.maigveil.annotations.VeilProfileLevel
import io.github.maignardi.maigveil.annotations.VeilString
import io.github.maignardi.maigveil.annotations.VeilVirtualize
import java.security.MessageDigest

/**
 * Core business logic protected by all 6 MaigVeil layers.
 *
 * - `API_MASTER_KEY` and `HMAC_SALT` have their `ConstantValue` attributes stripped
 *   and decrypted via polymorphic ARX at class-init time.
 * - `computeLicenseChecksum` is compiled to shuffled VM bytecode and executed in C++20.
 * - `evaluateRiskScore` is flattened into a `LOOKUPSWITCH` state machine with Level 2 opaque predicates.
 * - `digestSha256Hex` has its `java/security/MessageDigest` calls hidden behind `INVOKEDYNAMIC`.
 */
@VeilObfuscate(profile = VeilProfileLevel.PARANOID)
@VeilString(zeroTrace = true)
object ProtectedVaultEngine {

    const val API_MASTER_KEY: String = "mv_live_9f82c1a7_tier1_shield_key"
    const val HMAC_SALT: String = "MaigVeil::2026::ZeroTrace::Entropy"

    @JvmStatic
    fun getMaskedApiKey(): String {
        val key = API_MASTER_KEY
        return if (key.length > 10) "${key.take(8)}...${key.takeLast(4)}" else key
    }

    /**
     * Executed inside the native C++20 `libmaigveil.so` VM with per-build shuffled opcodes.
     */
    @VeilVirtualize
    @JvmStatic
    fun computeLicenseChecksum(userId: Int, salt: Int): Int {
        var acc = (userId xor 0x5A3C9E11) + (salt * 31)
        for (round in 0 until 8) {
            acc = ((acc shl 5) or (acc ushr 27)) xor (round * 0x9E3779B1.toInt())
            acc += (salt ushr (round and 7))
        }
        return acc and 0x7FFFFFFF
    }

    /**
     * Protected by Control Flow Flattening + Level 2 Mathematical Opaque Predicates.
     */
    @VeilControlFlow(flatteningProbability = 100, opaquePredicatesLevel = 2)
    @JvmStatic
    fun evaluateRiskScore(amount: Int, velocity: Int, trustLevel: Int): Int {
        var score = 10
        if (amount > 10_000) {
            score += 45
        } else if (amount > 2_500) {
            score += 20
        } else {
            score += 5
        }

        if (velocity > 5) {
            score += 30
        } else {
            score += velocity * 3
        }

        score -= trustLevel * 8
        return if (score < 0) 0 else if (score > 100) 100 else score
    }

    /**
     * Sensitive `java.security.MessageDigest` calls are rewritten to `INVOKEDYNAMIC`
     * at compile time, removing static call-graph edges in JADX.
     */
    @JvmStatic
    fun digestSha256Hex(input: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val bytes = md.digest(input.toByteArray(Charsets.UTF_8))
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }

    /**
     * Excluded from bytecode transforms for baseline comparison in benchmarks.
     */
    @VeilIgnore
    @JvmStatic
    fun baselineComputeLicenseChecksum(userId: Int, salt: Int): Int {
        var acc = (userId xor 0x5A3C9E11) + (salt * 31)
        for (round in 0 until 8) {
            acc = ((acc shl 5) or (acc ushr 27)) xor (round * 0x9E3779B1.toInt())
            acc += (salt ushr (round and 7))
        }
        return acc and 0x7FFFFFFF
    }
}
