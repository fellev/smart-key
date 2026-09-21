package com.example.smart_key.protocol

import org.json.JSONObject
import java.io.File

/**
 * Loads the golden vectors from `shared-protocols/test-vectors/`.
 *
 * The same files drive the firmware host tests, so if either side ever drifts
 * from the specification, one of the two suites fails.
 *
 * Regenerate them with:
 *     python3 shared-protocols/tools/gen_test_vectors.py
 */
object SharedVectors {

    /** Root of the shared-protocols folder, injected by build.gradle.kts. */
    private val root: File by lazy {
        val fromProperty = System.getProperty("smartkey.sharedProtocols")
        val candidates = listOfNotNull(
            fromProperty?.let { File(it) },
            File("../../shared-protocols"),
            File("../shared-protocols")
        )
        candidates.firstOrNull { it.isDirectory }
            ?: error(
                "cannot find the shared-protocols folder; tried " +
                    candidates.joinToString { it.absolutePath }
            )
    }

    val handshake: JSONObject by lazy { load("handshake.json") }
    val pairing: JSONObject by lazy { load("pairing.json") }

    private fun load(name: String): JSONObject {
        val file = File(root, "test-vectors/$name")
        require(file.isFile) { "missing test vector file: ${file.absolutePath}" }
        return JSONObject(file.readText())
    }
}

/** Hexadecimal helpers shared by the test suites. */
fun String.decodeHex(): ByteArray {
    require(length % 2 == 0) { "hex string must have an even length" }
    return ByteArray(length / 2) {
        ((Character.digit(this[it * 2], 16) shl 4) or Character.digit(this[it * 2 + 1], 16))
            .toByte()
    }
}

fun ByteArray.encodeHex(): String = joinToString("") { "%02x".format(it) }
