package com.b2y4n.vc.sdjwt.crypto

import java.security.MessageDigest
import java.util.Base64

/**
 * Abstraction for cryptographic hash operations used throughout the SD-JWT lifecycle.
 *
 * Adheres to Dependency Inversion by decoupling the hashing strategy from consumers
 * such as [com.b2y4n.vc.sdjwt.issuer.PayloadConcealer] and [com.b2y4n.vc.sdjwt.verifier.PayloadReconstructor],
 * allowing alternative algorithms (e.g., SHA-384, SHA-512) to be injected without modifying
 * orchestration logic.
 *
 * Implementations must produce digests compatible with the `_sd_alg` claim as defined in
 * [RFC 9901 Section 5.1](https://www.rfc-editor.org/rfc/rfc9901.html#section-5.1).
 */
interface Hasher {
    /**
     * The registered name of the hash algorithm as it appears in the JWT `_sd_alg` claim.
     *
     * Must conform to the IANA "Hash Function Textual Names" registry
     * (e.g., `"sha-256"`, `"sha-384"`).
     */
    val algorithmName: String

    /**
     * The length of the generated hash digest in bytes.
     *
     * Used to produce correctly sized random decoy padding bytes when generating
     * dummy digests in [com.b2y4n.vc.sdjwt.issuer.PayloadConcealer].
     */
    val digestSizeBytes: Int

    /**
     * Hashes the given string input and returns the result as a URL-safe Base64 encoded string
     * without padding.
     *
     * @param input The raw string to hash (typically a Base64url-encoded disclosure).
     * @return The URL-safe Base64 encoded hash digest without trailing `=` padding.
     */
    fun hashBase64Url(input: String): String
}

/**
 * Default SHA-256 implementation of the [Hasher] interface.
 *
 * Uses [java.security.MessageDigest] with the `"SHA-256"` algorithm to compute a 32-byte
 * digest, then encodes the result as a URL-safe Base64 string without padding. Input is
 * encoded using US-ASCII as required by the SD-JWT specification.
 */
class Sha256Hasher : Hasher {
    override val algorithmName: String = "sha-256"
    override val digestSizeBytes: Int = 32

    /**
     * Computes the SHA-256 hash of [input] encoded as US-ASCII bytes.
     *
     * @param input The raw string to hash.
     * @return The URL-safe Base64 encoded SHA-256 digest without padding.
     */
    override fun hashBase64Url(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(input.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes)
    }
}
