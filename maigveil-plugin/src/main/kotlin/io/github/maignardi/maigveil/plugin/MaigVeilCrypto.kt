package io.github.maignardi.maigveil.plugin

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Cryptographic primitives and binary vault serialization for MaigVeil's build-time pipeline.
 * All algorithms match `crypto_engine.cpp` in `:maigveil-runtime` byte-for-byte.
 */
object MaigVeilCrypto {

    private val WB_MASTER_LANES = longArrayOf(
        0x4D6169675665696CL,
        -0x5C06ED3B77FE2185L, // 0xA3F912C48801DE7BUL
        0x5E71B0993C44A21FL,
        -0x6E27B1D890FA3C76L  // 0x91D84E276F05C38AUL
    )

    fun whiteBoxMaster(): ByteArray {
        val out = ByteArray(32)
        for (i in 0 until 4) {
            val lane = WB_MASTER_LANES[i]
            for (b in 0 until 8) {
                out[i * 8 + b] = ((lane ushr ((7 - b) * 8)) and 0xFFL).toByte()
            }
        }
        return out
    }

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val prk = hmacSha256(effectiveSalt, ikm)
        val tIn = ByteArray(info.size + 1)
        System.arraycopy(info, 0, tIn, 0, info.size)
        tIn[info.size] = 0x01
        return hmacSha256(prk, tIn)
    }

    fun deriveSessionKey(certSha256: ByteArray, buildSeed: ByteArray): ByteArray {
        require(certSha256.size == 32) { "certSha256 must be 32 bytes" }
        require(buildSeed.size == 32) { "buildSeed must be 32 bytes" }
        val ikm = ByteArray(64)
        System.arraycopy(certSha256, 0, ikm, 0, 32)
        System.arraycopy(whiteBoxMaster(), 0, ikm, 32, 32)
        return hkdfSha256(ikm, buildSeed, "MaigVeil-v1-Session".toByteArray(Charsets.UTF_8))
    }

    fun fnv1a32(str: String): Int {
        var h = 0x811c9dc5.toInt()
        for (b in str.toByteArray(Charsets.UTF_8)) {
            h = (h xor (b.toInt() and 0xFF)) * 0x01000193
        }
        return h
    }

    private fun rotl32(v: Int, n: Int): Int {
        val r = n and 31
        return (v shl r) or (v ushr (32 - r))
    }

    private fun rotl8(v: Int, n: Int): Int {
        val r = n and 7
        val u = v and 0xFF
        return ((u shl r) or (u ushr ((8 - r) and 7))) and 0xFF
    }

    private fun rotr8(v: Int, n: Int): Int {
        val r = n and 7
        val u = v and 0xFF
        return ((u ushr r) or (u shl ((8 - r) and 7))) and 0xFF
    }

    private fun loadLe32(buf: ByteArray, off: Int): Int {
        return (buf[off].toInt() and 0xFF) or
            ((buf[off + 1].toInt() and 0xFF) shl 8) or
            ((buf[off + 2].toInt() and 0xFF) shl 16) or
            ((buf[off + 3].toInt() and 0xFF) shl 24)
    }

    private fun storeLe32(buf: ByteArray, off: Int, v: Int) {
        buf[off] = (v and 0xFF).toByte()
        buf[off + 1] = ((v ushr 8) and 0xFF).toByte()
        buf[off + 2] = ((v ushr 16) and 0xFF).toByte()
        buf[off + 3] = ((v ushr 24) and 0xFF).toByte()
    }

    private fun storeLe64(buf: ByteArray, off: Int, v: Long) {
        for (i in 0 until 8) {
            buf[off + i] = ((v ushr (i * 8)) and 0xFFL).toByte()
        }
    }

    /**
     * Polymorphic Dynamic ARX encryption matching `arx_decrypt` in `crypto_engine.cpp`.
     */
    fun arxEncrypt(
        sessionKey: ByteArray,
        schedule: ByteArray,
        classHash: Int,
        methodHash: Int,
        stringIndex: Int,
        plaintext: ByteArray
    ): ByteArray {
        val keyWords = IntArray(8) { w -> loadLe32(sessionKey, w * 4) }
        val out = ByteArray(plaintext.size)
        for (i in plaintext.indices) {
            val kRaw = keyWords[i and 7] xor
                (classHash * 0x9E3779B1.toInt()) xor
                (methodHash * 0x85EBCA6B.toInt()) xor
                (stringIndex * 0xC2B2AE35.toInt()) xor
                i
            val k = rotl32(kRaw, i and 31)
            val kByte = k and 0xFF

            var x = plaintext[i].toInt() and 0xFF
            for (s in 0 until 8) {
                val opByte = schedule[s].toInt() and 0xFF
                val opType = (opByte ushr 5) and 0x07
                val param = opByte and 0x1F
                x = when (opType % 6) {
                    0 -> (x + ((kByte + param) and 0xFF)) and 0xFF
                    1 -> x xor ((kByte xor param) and 0xFF)
                    2 -> rotl8(x, param and 7)
                    3 -> rotr8(x, param and 7)
                    4 -> (x + ((i * (param or 1)) and 0xFF)) and 0xFF
                    else -> x xor ((k ushr (param and 24)) and 0xFF)
                }
            }
            out[i] = x.toByte()
        }
        return out
    }

    private fun chacha20Block(key: ByteArray, counter: Int, nonce: ByteArray): ByteArray {
        val st = IntArray(16)
        st[0] = 0x61707865
        st[1] = 0x3320646E
        st[2] = 0x79622D32
        st[3] = 0x6B206574
        for (i in 0 until 8) st[4 + i] = loadLe32(key, i * 4)
        st[12] = counter
        for (i in 0 until 3) st[13 + i] = loadLe32(nonce, i * 4)

        val x = st.copyOf()
        fun qr(a: Int, b: Int, c: Int, d: Int) {
            x[a] += x[b]; x[d] = rotl32(x[d] xor x[a], 16)
            x[c] += x[d]; x[b] = rotl32(x[b] xor x[c], 12)
            x[a] += x[b]; x[d] = rotl32(x[d] xor x[a], 8)
            x[c] += x[d]; x[b] = rotl32(x[b] xor x[c], 7)
        }
        repeat(10) {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        val out = ByteArray(64)
        for (i in 0 until 16) storeLe32(out, i * 4, x[i] + st[i])
        return out
    }

    private class Poly1305(key32: ByteArray) {
        private val r = LongArray(5)
        private val h = LongArray(5)
        private val pad = LongArray(4)

        init {
            r[0] = (loadLe32(key32, 0).toLong() and 0xFFFFFFFFL) and 0x3FFFFFFL
            r[1] = ((loadLe32(key32, 3).toLong() and 0xFFFFFFFFL) ushr 2) and 0x3FFFF03L
            r[2] = ((loadLe32(key32, 6).toLong() and 0xFFFFFFFFL) ushr 4) and 0x3FFC0FFL
            r[3] = ((loadLe32(key32, 9).toLong() and 0xFFFFFFFFL) ushr 6) and 0x3F03FFFL
            r[4] = ((loadLe32(key32, 12).toLong() and 0xFFFFFFFFL) ushr 8) and 0x00FFFFFL
            for (i in 0 until 4) {
                pad[i] = loadLe32(key32, 16 + i * 4).toLong() and 0xFFFFFFFFL
            }
        }

        private fun block(m: ByteArray, off: Int, len: Int, isPartial: Boolean) {
            val tmp = ByteArray(16)
            System.arraycopy(m, off, tmp, 0, len)
            val hibit = if (isPartial) 0L else (1L shl 24)
            if (isPartial && len < 16) tmp[len] = 1

            h[0] += (loadLe32(tmp, 0).toLong() and 0xFFFFFFFFL) and 0x3FFFFFFL
            h[1] += ((loadLe32(tmp, 3).toLong() and 0xFFFFFFFFL) ushr 2) and 0x3FFFFFFL
            h[2] += ((loadLe32(tmp, 6).toLong() and 0xFFFFFFFFL) ushr 4) and 0x3FFFFFFL
            h[3] += ((loadLe32(tmp, 9).toLong() and 0xFFFFFFFFL) ushr 6) and 0x3FFFFFFL
            h[4] += ((loadLe32(tmp, 12).toLong() and 0xFFFFFFFFL) ushr 8) or hibit

            val r0 = r[0]; val r1 = r[1]; val r2 = r[2]; val r3 = r[3]; val r4 = r[4]
            val s1 = r1 * 5; val s2 = r2 * 5; val s3 = r3 * 5; val s4 = r4 * 5

            val d0 = h[0] * r0 + h[1] * s4 + h[2] * s3 + h[3] * s2 + h[4] * s1
            val d1 = h[0] * r1 + h[1] * r0 + h[2] * s4 + h[3] * s3 + h[4] * s2
            val d2 = h[0] * r2 + h[1] * r1 + h[2] * r0 + h[3] * s4 + h[4] * s3
            val d3 = h[0] * r3 + h[1] * r2 + h[2] * r1 + h[3] * r0 + h[4] * s4
            val d4 = h[0] * r4 + h[1] * r3 + h[2] * r2 + h[3] * r1 + h[4] * r0

            var c = d0 ushr 26; h[0] = d0 and 0x3FFFFFFL
            val t1 = d1 + c; c = t1 ushr 26; h[1] = t1 and 0x3FFFFFFL
            val t2 = d2 + c; c = t2 ushr 26; h[2] = t2 and 0x3FFFFFFL
            val t3 = d3 + c; c = t3 ushr 26; h[3] = t3 and 0x3FFFFFFL
            val t4 = d4 + c; c = t4 ushr 26; h[4] = t4 and 0x3FFFFFFL
            h[0] += c * 5
            c = h[0] ushr 26; h[0] = h[0] and 0x3FFFFFFL
            h[1] += c
        }

        fun updatePadded(data: ByteArray) {
            if (data.isEmpty()) return
            var off = 0
            while (off + 16 <= data.size) {
                block(data, off, 16, false)
                off += 16
            }
            if (off < data.size) {
                val padded = ByteArray(16)
                System.arraycopy(data, off, padded, 0, data.size - off)
                block(padded, 0, 16, false)
            }
        }

        fun update(data: ByteArray) {
            var off = 0
            while (off + 16 <= data.size) {
                block(data, off, 16, false)
                off += 16
            }
            if (off < data.size) {
                block(data, off, data.size - off, true)
            }
        }

        fun finish(): ByteArray {
            var c = h[1] ushr 26; h[1] = h[1] and 0x3FFFFFFL
            h[2] += c; c = h[2] ushr 26; h[2] = h[2] and 0x3FFFFFFL
            h[3] += c; c = h[3] ushr 26; h[3] = h[3] and 0x3FFFFFFL
            h[4] += c; c = h[4] ushr 26; h[4] = h[4] and 0x3FFFFFFL
            h[0] += c * 5; c = h[0] ushr 26; h[0] = h[0] and 0x3FFFFFFL
            h[1] += c

            val g = LongArray(5)
            g[0] = h[0] + 5; c = g[0] ushr 26; g[0] = g[0] and 0x3FFFFFFL
            g[1] = h[1] + c; c = g[1] ushr 26; g[1] = g[1] and 0x3FFFFFFL
            g[2] = h[2] + c; c = g[2] ushr 26; g[2] = g[2] and 0x3FFFFFFL
            g[3] = h[3] + c; c = g[3] ushr 26; g[3] = g[3] and 0x3FFFFFFL
            g[4] = h[4] + c - (1L shl 26)

            val mask = ((g[4] ushr 63) - 1L)
            for (i in 0 until 5) {
                h[i] = (h[i] and mask.inv()) or (g[i] and mask)
            }

            val f0 = (h[0] or (h[1] shl 26)) and 0xFFFFFFFFL
            val f1 = ((h[1] ushr 6) or (h[2] shl 20)) and 0xFFFFFFFFL
            val f2 = ((h[2] ushr 12) or (h[3] shl 14)) and 0xFFFFFFFFL
            val f3 = ((h[3] ushr 18) or (h[4] shl 8)) and 0xFFFFFFFFL

            var acc = f0 + pad[0]
            val out0 = acc.toInt()
            acc = f1 + pad[1] + (acc ushr 32)
            val out1 = acc.toInt()
            acc = f2 + pad[2] + (acc ushr 32)
            val out2 = acc.toInt()
            acc = f3 + pad[3] + (acc ushr 32)
            val out3 = acc.toInt()

            val tag = ByteArray(16)
            storeLe32(tag, 0, out0)
            storeLe32(tag, 4, out1)
            storeLe32(tag, 8, out2)
            storeLe32(tag, 12, out3)
            return tag
        }
    }

    /**
     * RFC 8439 ChaCha20-Poly1305 AEAD encryption.
     */
    fun chacha20Poly1305Encrypt(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray
    ): Pair<ByteArray, ByteArray> {
        val polyKeyBlock = chacha20Block(key, 0, nonce)
        val polyKey = polyKeyBlock.copyOf(32)

        val ciphertext = ByteArray(plaintext.size)
        var counter = 1
        var off = 0
        while (off < plaintext.size) {
            val ks = chacha20Block(key, counter++, nonce)
            val chunk = minOf(64, plaintext.size - off)
            for (i in 0 until chunk) {
                ciphertext[off + i] = (plaintext[off + i].toInt() xor ks[i].toInt()).toByte()
            }
            off += chunk
        }

        val poly = Poly1305(polyKey)
        poly.updatePadded(aad)
        poly.updatePadded(ciphertext)
        val lens = ByteArray(16)
        storeLe64(lens, 0, aad.size.toLong())
        storeLe64(lens, 8, ciphertext.size.toLong())
        poly.update(lens)

        return ciphertext to poly.finish()
    }
}

/**
 * Per-build cryptographic seed, polymorphic ARX schedule, shuffled VM opcode table,
 * and bound APK signing certificate SHA-256.
 */
class BuildSeedData(
    val buildEntropySeed: ByteArray,
    val arxSchedule: ByteArray,
    /** Maps shuffledByte (0..255) -> canonicalVmOp (0..255). */
    val opcodeDecodeTable: ByteArray,
    val certSha256: ByteArray
) {
    /** Maps canonicalVmOp (0..255) -> shuffledByte (0..255). */
    val opcodeEncodeTable: ByteArray = ByteArray(256).also { enc ->
        for (shuffled in 0 until 256) {
            val canonical = opcodeDecodeTable[shuffled].toInt() and 0xFF
            enc[canonical] = shuffled.toByte()
        }
    }

    val sessionKey: ByteArray by lazy {
        MaigVeilCrypto.deriveSessionKey(certSha256, buildEntropySeed)
    }

    fun writeTo(file: File) {
        file.parentFile?.mkdirs()
        DataOutputStream(file.outputStream().buffered()).use { out ->
            out.write(buildEntropySeed)
            out.write(arxSchedule)
            out.write(opcodeDecodeTable)
            out.write(certSha256)
        }
    }

    companion object {
        fun generate(certSha256: ByteArray, rng: SecureRandom = SecureRandom()): BuildSeedData {
            val seed = ByteArray(32).also { rng.nextBytes(it) }
            val schedule = ByteArray(8).also { rng.nextBytes(it) }
            val perm = (0 until 256).toMutableList()
            perm.shuffle(rng)
            val decode = ByteArray(256) { i -> perm[i].toByte() }
            return BuildSeedData(seed, schedule, decode, certSha256)
        }

        fun readFrom(file: File): BuildSeedData {
            DataInputStream(file.inputStream().buffered()).use { inp ->
                val seed = ByteArray(32).also { inp.readFully(it) }
                val schedule = ByteArray(8).also { inp.readFully(it) }
                val decode = ByteArray(256).also { inp.readFully(it) }
                val cert = ByteArray(32).also { inp.readFully(it) }
                return BuildSeedData(seed, schedule, decode, cert)
            }
        }
    }
}

data class VaultStringEntry(
    val id: Int,
    val classHash: Int,
    val methodHash: Int,
    val strIndex: Int,
    val cipherBytes: ByteArray
)

sealed class VmConstPoolEntry {
    data class IntVal(val v: Int) : VmConstPoolEntry()
    data class LongVal(val v: Long) : VmConstPoolEntry()
    data class StringId(val strId: Int) : VmConstPoolEntry()
    data class MethodRef(val owner: String, val name: String, val desc: String) : VmConstPoolEntry()
}

data class VaultVmProgram(
    val programId: Int,
    val paramCount: Int,
    val maxLocals: Int,
    val maxStack: Int,
    val returnType: Int,
    val constPool: List<VmConstPoolEntry>,
    val bytecode: ByteArray
)

object VaultWriter {

    private fun writeLe16(out: ByteArrayOutputStream, v: Int) {
        out.write(v and 0xFF)
        out.write((v ushr 8) and 0xFF)
    }

    private fun writeLe32(out: ByteArrayOutputStream, v: Int) {
        out.write(v and 0xFF)
        out.write((v ushr 8) and 0xFF)
        out.write((v ushr 16) and 0xFF)
        out.write((v ushr 24) and 0xFF)
    }

    private fun writeLe64(out: ByteArrayOutputStream, v: Long) {
        for (i in 0 until 8) {
            out.write(((v ushr (i * 8)) and 0xFFL).toInt())
        }
    }

    private fun writeStr(out: ByteArrayOutputStream, s: String) {
        val bytes = s.toByteArray(Charsets.UTF_8)
        writeLe16(out, bytes.size)
        out.write(bytes)
    }

    fun writeVault(
        outFile: File,
        seedData: BuildSeedData,
        strings: List<VaultStringEntry>,
        vmPrograms: List<VaultVmProgram>,
        flags: Int = 0x03
    ) {
        val header = ByteBuffer.allocate(48).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("MVLT".toByteArray(Charsets.US_ASCII))
            putInt(1) // version
            putInt(flags)
            putInt(0) // reserved
            put(seedData.buildEntropySeed)
        }.array()

        val bodyOut = ByteArrayOutputStream()
        bodyOut.write(seedData.arxSchedule)
        bodyOut.write(seedData.opcodeDecodeTable)

        writeLe32(bodyOut, strings.size)
        for (s in strings) {
            writeLe32(bodyOut, s.id)
            writeLe32(bodyOut, s.classHash)
            writeLe32(bodyOut, s.methodHash)
            writeLe32(bodyOut, s.strIndex)
            writeLe32(bodyOut, s.cipherBytes.size)
            bodyOut.write(s.cipherBytes)
        }

        writeLe32(bodyOut, vmPrograms.size)
        for (p in vmPrograms) {
            writeLe32(bodyOut, p.programId)
            writeLe16(bodyOut, p.paramCount)
            writeLe16(bodyOut, p.maxLocals)
            writeLe16(bodyOut, p.maxStack)
            bodyOut.write(p.returnType and 0xFF)
            writeLe16(bodyOut, p.constPool.size)
            for (c in p.constPool) {
                when (c) {
                    is VmConstPoolEntry.IntVal -> {
                        bodyOut.write(1)
                        writeLe32(bodyOut, c.v)
                    }
                    is VmConstPoolEntry.LongVal -> {
                        bodyOut.write(2)
                        writeLe64(bodyOut, c.v)
                    }
                    is VmConstPoolEntry.StringId -> {
                        bodyOut.write(5)
                        writeLe32(bodyOut, c.strId)
                    }
                    is VmConstPoolEntry.MethodRef -> {
                        bodyOut.write(6)
                        writeStr(bodyOut, c.owner)
                        writeStr(bodyOut, c.name)
                        writeStr(bodyOut, c.desc)
                    }
                }
            }
            writeLe32(bodyOut, p.bytecode.size)
            bodyOut.write(p.bytecode)
        }

        val nonce = seedData.buildEntropySeed.copyOf(12)
        val (cipherBody, tag) = MaigVeilCrypto.chacha20Poly1305Encrypt(
            key = seedData.sessionKey,
            nonce = nonce,
            aad = header,
            plaintext = bodyOut.toByteArray()
        )

        outFile.parentFile?.mkdirs()
        outFile.outputStream().buffered().use { fos ->
            fos.write(header)
            fos.write(cipherBody)
            fos.write(tag)
        }
    }
}
