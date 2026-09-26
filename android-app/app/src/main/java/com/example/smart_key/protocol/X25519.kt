package com.example.smart_key.protocol

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.KeyAgreement

/**
 * X25519 key agreement for pairing (pairing-spec.md §2).
 *
 * Uses the platform XDH provider (API 33+; the app targets API 36) and converts
 * between Java's BigInteger u-coordinate and the little endian 32 byte wire
 * format defined by RFC 7748.
 */
object X25519 {

    private const val ALGORITHM = "XDH"
    private val PARAM_SPEC = NamedParameterSpec.X25519
    private const val KEY_BYTES = SmartKeyProtocol.PUBKEY_SIZE

    /** 12 byte SubjectPublicKeyInfo header + the 32 byte u-coordinate. */
    private const val X509_X25519_SIZE = 12 + KEY_BYTES

    /** An ephemeral pairing key pair. */
    class KeyPair(val privateKey: PrivateKey, val publicKeyBytes: ByteArray)

    fun generateKeyPair(): KeyPair {
        val pair = KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair()
        return KeyPair(pair.private, encodePublicKey(pair.public))
    }

    /**
     * Compute the shared secret.
     * @throws IllegalStateException when the result is all zero (low order point).
     */
    fun computeShared(privateKey: PrivateKey, peerPublicKey: ByteArray): ByteArray {
        require(peerPublicKey.size == KEY_BYTES) { "peer public key must be $KEY_BYTES bytes" }
        val agreement = KeyAgreement.getInstance(ALGORITHM).apply {
            init(privateKey)
            doPhase(decodePublicKey(peerPublicKey), true)
        }
        val shared = agreement.generateSecret()
        check(shared.any { it.toInt() != 0 }) { "rejected all-zero X25519 shared secret" }
        return shared
    }

    /** Build a [PrivateKey] from raw little endian scalar bytes (test support). */
    private val X25519_PKCS8_PREFIX = byteArrayOf(
        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03,
        0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20
    )

    fun privateKeyFromBytes(scalar: ByteArray): PrivateKey {
        require(scalar.size == KEY_BYTES) { "scalar must be $KEY_BYTES bytes" }
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(
            PKCS8EncodedKeySpec(X25519_PKCS8_PREFIX + scalar)
        )
    }

    /** Derive the public key of a raw private scalar. */
    fun publicKeyFromPrivate(scalar: ByteArray): ByteArray {
        // The JCA offers no direct "scalar * base point", so agree with the
        // base point u = 9, which is exactly the definition of the public key.
        val basePoint = ByteArray(KEY_BYTES).also { it[0] = 9 }
        return computeShared(privateKeyFromBytes(scalar), basePoint)
    }

    /** Little endian wire format -> JCA public key. */
    private val X25519_SPKI_PREFIX = byteArrayOf(
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00
    )

    private fun decodePublicKey(bytes: ByteArray): PublicKey {
        require(bytes.size == KEY_BYTES)
        return KeyFactory.getInstance(ALGORITHM).generatePublic(
            X509EncodedKeySpec(X25519_SPKI_PREFIX + bytes)
        )
    }

    /**
     * JCA public key -> 32 byte little endian wire format (RFC 7748).
     *
     * An X25519 SubjectPublicKeyInfo is 44 bytes: a 12 byte header followed by
     * the 32 byte u-coordinate, already little endian, so the raw key is simply
     * the tail.
     *
     * Deliberately *not* done via `XECPublicKey.getU()`: that returns a
     * BigInteger whose `toByteArray()` is big endian, which would silently
     * reverse the key. The bytes would still look valid and pairing would fail
     * much later, at the confirmation check, looking like a wrong pairing code.
     */

    private fun encodePublicKey(key: PublicKey): ByteArray {
        val encoded = key.encoded
        require(key.format == "X.509" && encoded.size == 44) {
            "Expected an X.509-encoded X25519 public key"
        }
        return encoded.copyOfRange(encoded.size - KEY_BYTES, encoded.size)
    }
}
