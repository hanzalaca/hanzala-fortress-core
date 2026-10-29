package com.hanzala.fortress.vault

import com.goterl.lazysodium.SodiumJava
import com.sun.jna.NativeLong

/** libsodium through lazysodium-java (bundled native library), for JVM tests only. */
object JvmSodium : Sodium {
    private val native = SodiumJava().also { check(it.sodium_init() >= 0) { "sodium_init failed" } }
    private const val ARGON2ID13 = 2

    override fun randomBytes(count: Int) = ByteArray(count).also { if (count > 0) native.randombytes_buf(it, count) }

    override fun argon2id13(outputLength: Int, password: ByteArray, salt: ByteArray, opsLimit: Long, memLimit: Long): ByteArray? {
        val out = ByteArray(outputLength)
        val rc = native.crypto_pwhash(
            out, outputLength.toLong(), password, password.size.toLong(), salt, opsLimit, NativeLong(memLimit), ARGON2ID13,
        )
        return if (rc == 0) out else null
    }

    override fun secretboxEasy(message: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        val out = ByteArray(message.size + 16)
        check(native.crypto_secretbox_easy(out, message, message.size.toLong(), nonce, key) == 0)
        return out
    }

    override fun secretboxOpenEasy(boxed: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray? {
        if (boxed.size < 16) return null
        val out = ByteArray(boxed.size - 16)
        return if (native.crypto_secretbox_open_easy(out, boxed, boxed.size.toLong(), nonce, key) == 0) out else null
    }

    override fun xchacha20poly1305Encrypt(message: ByteArray, ad: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        val out = ByteArray(message.size + 16)
        check(
            native.crypto_aead_xchacha20poly1305_ietf_encrypt(
                out, null, message, message.size.toLong(), ad, ad.size.toLong(), null, nonce, key,
            ) == 0,
        )
        return out
    }

    override fun xchacha20poly1305Decrypt(sealed: ByteArray, ad: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray? {
        if (sealed.size < 16) return null
        val out = ByteArray(sealed.size - 16)
        val rc = native.crypto_aead_xchacha20poly1305_ietf_decrypt(
            out, null, null, sealed, sealed.size.toLong(), ad, ad.size.toLong(), nonce, key,
        )
        return if (rc == 0) out else null
    }
}
