package com.example.smart_key.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coverage for [X25519.generateKeyPair].
 *
 * This path had none: every other test builds keys through
 * `privateKeyFromBytes`, which supplies the curve parameters explicitly. So
 * the golden vectors all passed while the *only* function real pairing uses to
 * make a key was never exercised — and it was missing its `initialize()` call.
 */
class X25519KeyGenTest {

    @Test
    fun `generates a usable 32 byte public key`() {
        val pair = X25519.generateKeyPair()

        assertNotNull(pair.privateKey)
        assertEquals(
            "a 56 byte key means X448 was generated instead of X25519",
            SmartKeyProtocol.PUBKEY_SIZE,
            pair.publicKeyBytes.size
        )
        assertFalse(
            "public key must not be all zero",
            pair.publicKeyBytes.all { it == 0.toByte() }
        )
    }

    @Test
    fun `successive key pairs differ`() {
        val a = X25519.generateKeyPair()
        val b = X25519.generateKeyPair()
        assertFalse(
            "two generated keys must not be identical",
            a.publicKeyBytes.contentEquals(b.publicKeyBytes)
        )
    }

    @Test
    fun `a generated key pair completes a real key agreement`() {
        // The end-to-end property that matters: two independently generated
        // pairs must agree on the same shared secret.
        val phone = X25519.generateKeyPair()
        val lock = X25519.generateKeyPair()

        val fromPhone = X25519.computeShared(phone.privateKey, lock.publicKeyBytes)
        val fromLock = X25519.computeShared(lock.privateKey, phone.publicKeyBytes)

        assertArrayEquals("both sides must derive the same secret", fromPhone, fromLock)
        assertEquals(SmartKeyProtocol.KEY_SIZE, fromPhone.size)
    }

    @Test
    fun `the generated public key matches the one derived from its own scalar`() {
        // Cross-checks encodePublicKey() against the independent
        // publicKeyFromPrivate() path, which multiplies by the base point.
        // A byte-order mistake in either would show up here.
        val pair = X25519.generateKeyPair()

        // Agreeing our own private key with the base point yields our public
        // key, so this reproduces encodePublicKey() by a different route.
        val basePoint = ByteArray(SmartKeyProtocol.PUBKEY_SIZE).also { it[0] = 9 }
        val derived = X25519.computeShared(pair.privateKey, basePoint)

        assertArrayEquals(
            "encodePublicKey() disagrees with scalar-times-base-point; " +
                "likely a little/big endian mix-up",
            pair.publicKeyBytes,
            derived
        )
    }

    @Test
    fun `generated keys interoperate with keys built from raw scalars`() {
        // Mixed path: one side generated, the other from fixed bytes, which is
        // what happens when the phone pairs with the firmware.
        val generated = X25519.generateKeyPair()

        val scalar = ByteArray(SmartKeyProtocol.KEY_SIZE) { (it + 1).toByte() }
        val fixedPriv = X25519.privateKeyFromBytes(scalar)
        val fixedPub = X25519.publicKeyFromPrivate(scalar)

        val a = X25519.computeShared(generated.privateKey, fixedPub)
        val b = X25519.computeShared(fixedPriv, generated.publicKeyBytes)

        assertArrayEquals(a, b)
    }

    @Test
    fun `an all-zero peer key is rejected`() {
        // Low order point: the shared secret would be all zero, which must not
        // be accepted (security-model.md §3).
        val pair = X25519.generateKeyPair()
        val zeroPeer = ByteArray(SmartKeyProtocol.PUBKEY_SIZE)

        val failed = runCatching {
            X25519.computeShared(pair.privateKey, zeroPeer)
        }.isFailure

        assertTrue("an all-zero shared secret must be rejected", failed)
    }

    @Test
    fun `a wrong sized peer key is rejected`() {
        val pair = X25519.generateKeyPair()
        val failed = runCatching {
            X25519.computeShared(pair.privateKey, ByteArray(16))
        }.isFailure
        assertTrue(failed)
    }
}
