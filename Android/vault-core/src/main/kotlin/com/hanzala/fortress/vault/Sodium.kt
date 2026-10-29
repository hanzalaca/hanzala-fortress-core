package com.hanzala.fortress.vault

/**
 * The libsodium calls the v2 format uses (spec §1). The Android app passes a
 * lazysodium-android binding and the JVM tests pass lazysodium-java, so this
 * module never links a native library itself.
 *
 * Every "open"/"decrypt"/"derive" call returns null on failure instead of
 * throwing, so callers can treat all failures alike.
 */
interface Sodium {
    fun randomBytes(count: Int): ByteArray

    /** `crypto_pwhash` with `crypto_pwhash_ALG_ARGON2ID13`. */
    fun argon2id13(outputLength: Int, password: ByteArray, salt: ByteArray, opsLimit: Long, memLimit: Long): ByteArray?

    /** `crypto_secretbox_easy` (XSalsa20-Poly1305): returns tag || ciphertext. */
    fun secretboxEasy(message: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray

    fun secretboxOpenEasy(boxed: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray?

    /** `crypto_aead_xchacha20poly1305_ietf_encrypt`: returns ciphertext || tag. */
    fun xchacha20poly1305Encrypt(message: ByteArray, ad: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray

    fun xchacha20poly1305Decrypt(sealed: ByteArray, ad: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray?
}

class VaultFormatException(message: String) : Exception(message)

/** The password KDF could not run (libsodium refused, usually for lack of memory); no slot was tried with it. */
class KeyDerivationException : Exception("could not derive the key (not enough memory?)")
