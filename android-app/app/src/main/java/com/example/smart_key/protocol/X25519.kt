package com.example.smart_key.protocol

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.XECPublicKey
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

    /** An ephemeral pairing key pair. */
    class KeyPair(val privateKey: PrivateKey, val publicKeyBytes: ByteArray)

    fun generateKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance(ALGORITHM).apply { initialize(PARAM_SPEC) }
        val pair = generator.generateKeyPair()
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
    fun privateKeyFromBytes(scalar: ByteArray): PrivateKey {
        require(scalar.size == KEY_BYTES) { "scalar must be $KEY_BYTES bytes" }
        return KeyFactory.getInstance(ALGORITHM)
            .generatePrivate(XECPrivateKeySpec(PARAM_SPEC, scalar.copyOf()))
    }

    /** Derive the public key of a raw private scalar. */
    fun publicKeyFromPrivate(scalar: ByteArray): ByteArray {
        // The JCA offers no direct "scalar * base point", so agree with the
        // base point u = 9, which is exactly the definition of the public key.
        val basePoint = ByteArray(KEY_BYTES).also { it[0] = 9 }
        return computeShared(privateKeyFromBytes(scalar), basePoint)
    }

    /** Little endian wire format -> JCA public key. */
    private fun decodePublicKey(bytes: ByteArray): PublicKey {
        val le = bytes.copyOf()
        le[KEY_BYTES - 1] = (le[KEY_BYTES - 1].toInt() and 0x7F).toByte() // clear the sign bit
        val u = BigInteger(1, le.reversedArray())
        return KeyFactory.getInstance(ALGORITHM)
            .generatePublic(XECPublicKeySpec(PARAM_SPEC, u))
    }

    /** JCA public key -> little endian wire format. */
    private fun encodePublicKey(key: PublicKey): ByteArray {
        val u = (key as XECPublicKey).u
        val big = u.toByteArray() // big endian, possibly with a leading zero
        val out = ByteArray(KEY_BYTES)
        var index = 0
        for (i in big.indices.reversed()) {
            if (index >= KEY_BYTES) break
            out[index++] = big[i]
        }
        return out
    }
}
