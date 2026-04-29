package com.b2y4n.vc.sdjwt.crypto

import java.security.MessageDigest
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals

class Sha256HasherTest {

    private val hasher = Sha256Hasher()

    @Test
    fun `algorithmName returns sha-256`() {
        assertEquals("sha-256", hasher.algorithmName)
    }

    @Test
    fun `digestSizeBytes returns 32`() {
        assertEquals(32, hasher.digestSizeBytes)
    }

    @Test
    fun `hashBase64Url produces correct SHA-256 digest for known input`() {
        // Known test vector: SHA-256 of "test" encoded as US-ASCII
        val input = "test"
        val expectedBytes = MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray(Charsets.US_ASCII))
        val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedBytes)

        assertEquals(expected, hasher.hashBase64Url(input))
    }

    @Test
    fun `hashBase64Url produces URL-safe output without padding`() {
        val result = hasher.hashBase64Url("some-disclosure-string")

        // Must not contain standard Base64 padding or non-URL-safe characters
        assert('=' !in result) { "Hash output must not contain Base64 padding" }
        assert('+' !in result) { "Hash output must be URL-safe (no '+' character)" }
        assert('/' !in result) { "Hash output must be URL-safe (no '/' character)" }
    }

    @Test
    fun `hashBase64Url is deterministic for same input`() {
        val input = "WyJzYWx0MTIzIiwgIm5hbWUiLCAiSm9obiJd"
        val first = hasher.hashBase64Url(input)
        val second = hasher.hashBase64Url(input)

        assertEquals(first, second, "Same input must always produce same hash")
    }

    @Test
    fun `hashBase64Url produces different outputs for different inputs`() {
        val hash1 = hasher.hashBase64Url("input_a")
        val hash2 = hasher.hashBase64Url("input_b")

        assert(hash1 != hash2) { "Different inputs must produce different hashes" }
    }

    @Test
    fun `hashBase64Url handles empty string input`() {
        // SHA-256 of empty string is well-known
        val expectedBytes = MessageDigest.getInstance("SHA-256")
            .digest("".toByteArray(Charsets.US_ASCII))
        val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedBytes)

        assertEquals(expected, hasher.hashBase64Url(""))
    }

    @Test
    fun `hashBase64Url matches RFC 9901 disclosure hashing convention`() {
        // Simulate a real disclosure: Base64url-encode a JSON array, then hash it
        val disclosureJson = """["salt123", "name", "John"]"""
        val encodedDisclosure = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(disclosureJson.toByteArray(Charsets.UTF_8))

        val hashResult = hasher.hashBase64Url(encodedDisclosure)

        // Manually compute the expected hash
        val digest = MessageDigest.getInstance("SHA-256")
        val expectedHash = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(digest.digest(encodedDisclosure.toByteArray(Charsets.US_ASCII)))

        assertEquals(expectedHash, hashResult)
    }
}
