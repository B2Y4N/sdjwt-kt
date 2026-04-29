package com.b2y4n.vc.sdjwt.parser

import java.security.MessageDigest
import java.util.Base64
import kotlin.test.*
import kotlin.test.Test
import kotlinx.serialization.json.*

class SdJwtParserTest {

    private val parser = SdJwtParser()

    @Test
    fun `parse valid SD-JWT without KB-JWT`() {
        // baseJwt~disclosure1~
        val baseJwt = "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.sig"
        val disclosureStr = """["salt123", "name", "John"]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())
        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = parser.parse(sdJwtString)
        assertTrue(result.isSuccess)
        val sdJwt = result.getOrThrow()

        assertEquals(baseJwt, sdJwt.jwt)
        assertNull(sdJwt.kbJwt)
        assertEquals(1, sdJwt.disclosures.size)

        val d = sdJwt.disclosures[0]
        assertEquals(encodedDisclosure, d.encoded)
        assertEquals("salt123", d.salt)
        assertEquals("name", d.claimName)
        assertEquals("John", (d.claimValue as JsonPrimitive).content)
    }

    @Test
    fun `parse valid SD-JWT with KB-JWT`() {
        val baseJwt = "eyJhbGciOiJFUzI1NiJ9.e30.sig"
        val kbJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.e30.kb_sig"
        val sdJwtString = "$baseJwt~$kbJwt"

        val result = parser.parse(sdJwtString)
        assertTrue(result.isSuccess)
        val sdJwt = result.getOrThrow()

        assertEquals(baseJwt, sdJwt.jwt)
        assertEquals(kbJwt, sdJwt.kbJwt)
        assertEquals(0, sdJwt.disclosures.size)
    }

    @Test
    fun `parse valid SD-JWT with array disclosure`() {
        val baseJwt = "eyJhbGciOiJFUzI1NiJ9.e30.sig"
        val disclosureStr = """["salt456", "ES256"]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())
        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = parser.parse(sdJwtString)
        assertTrue(result.isSuccess)
        val sdJwt = result.getOrThrow()

        val d = sdJwt.disclosures[0]
        assertEquals("salt456", d.salt)
        assertNull(d.claimName)
        assertEquals("ES256", (d.claimValue as JsonPrimitive).content)
    }

    @Test
    fun `parse throws IllegalArgumentException for badly formatted SD-JWT (no tildes)`() {
        val result = parser.parse("just.a.jwt.without.tilde")
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IllegalArgumentException)
    }

    @Test
    fun `parse throws for invalid base JWT (not 2 dots)`() {
        val sdJwtString = "not.a.jwt~encoded_disclosure~"
        val result = parser.parse(sdJwtString)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IllegalArgumentException)
    }

    @Test
    fun `parse throws for non-base64 disclosure`() {
        val sdJwtString = "some.base.jwt~not_base64!~"
        val result = parser.parse(sdJwtString)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IllegalArgumentException)
    }

    @Test
    fun `parse throws for bad JSON in disclosure`() {
        val badJson = "not_json"
        val encodedBad =
                Base64.getUrlEncoder().withoutPadding().encodeToString(badJson.toByteArray())
        val sdJwtString = "some.base.jwt~$encodedBad~"
        val result = parser.parse(sdJwtString)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IllegalArgumentException)
    }

    @Test
    fun `parse throws for invalid json array size`() {
        val badJson = """["salt"]""" // Only 1 element
        val encodedBad =
                Base64.getUrlEncoder().withoutPadding().encodeToString(badJson.toByteArray())
        val sdJwtString = "some.base.jwt~$encodedBad~"
        val result = parser.parse(sdJwtString)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IllegalArgumentException)
    }

    @Test
    fun `parse RFC 9901 A_1 Structured SD-JWT complex claimValue`() {
        val baseJwt = "eyJhbGciOiJFUzI1NiJ9.e30.sig"
        val disclosureStr = """["salt789", "address", {"locality":"NYC","country":"US"}]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())
        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = parser.parse(sdJwtString)
        assertTrue(result.isSuccess)
        val sdJwt = result.getOrThrow()

        val d = sdJwt.disclosures[0]
        assertEquals("address", d.claimName)
        assertTrue(d.claimValue is JsonObject)
        assertEquals("NYC", (d.claimValue)["locality"]?.let { (it as JsonPrimitive).content })
    }

    @Test
    fun `parse RFC 9901 A_2 Recursive Structured SD-JWT nested array`() {
        val baseJwt = "eyJhbGciOiJFUzI1NiJ9.e30.sig"
        val disclosureStr = """["salt999", "nationalities", ["US", "DE"]]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())
        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = parser.parse(sdJwtString)
        assertTrue(result.isSuccess)
        val sdJwt = result.getOrThrow()

        val d = sdJwt.disclosures[0]
        assertEquals("nationalities", d.claimName)
        assertTrue(d.claimValue is JsonArray)
        assertEquals("US", ((d.claimValue)[0] as JsonPrimitive).content)
    }

    @Test
    fun `parse extracts respective path for complex nested SD-JWT disclosures`() {
        val disclosureStr = """["salt123", "city", "NYC"]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())
        val hashStr =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(encodedDisclosure.toByteArray(Charsets.US_ASCII))
                        )

        // Create base payload with address mapping to the nested disclosure hash
        val payload = """{"address": {"_sd": ["$hashStr"]}}"""
        val base64Payload =
                Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())
        val baseJwt = "eyJhbGciOiJFUzI1NiJ9.$base64Payload.sig"
        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = parser.parse(sdJwtString)
        assertTrue(result.isSuccess)
        val sdJwt = result.getOrThrow()

        val d = sdJwt.disclosures[0]
        assertEquals("city", d.claimName)
        assertEquals(
                "address.city",
                d.path?.asString,
                "Parser should properly extract that city belongs inside address"
        )
    }

    @Test
    fun `parse fails for blank string`() {
        val result = parser.parse("   ")
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IllegalArgumentException)
        assertEquals(result.exceptionOrNull()?.message?.contains("blank"), true)
    }

    @Test
    fun `parse resolves array element disclosure paths via dot-dot-dot wrappers`() {
        val disclosureStr = """["saltArr", "swimming"]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())
        val hashStr =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(encodedDisclosure.toByteArray(Charsets.US_ASCII))
                        )

        val payload = """{"hobbies": ["reading", {"...": "$hashStr"}]}"""
        val base64Payload =
                Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())
        val baseJwt = "eyJhbGciOiJFUzI1NiJ9.$base64Payload.sig"
        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = parser.parse(sdJwtString)
        assertTrue(result.isSuccess)
        val sdJwt = result.getOrThrow()

        val d = sdJwt.disclosures[0]
        assertNull(d.claimName)
        assertEquals("hobbies[1]", d.path?.asString, "Array element should resolve to hobbies[1]")
    }

    @Test
    fun `parse leaves path null for disclosure whose hash is not in payload`() {
        val disclosureStr = """["saltOrphan", "orphan", "value"]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())

        // Payload has an _sd array, but with a DIFFERENT hash
        val payload = """{"_sd": ["completely_different_hash"]}"""
        val base64Payload =
                Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())
        val baseJwt = "eyJhbGciOiJFUzI1NiJ9.$base64Payload.sig"
        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = parser.parse(sdJwtString)
        assertTrue(result.isSuccess)
        val sdJwt = result.getOrThrow()

        val d = sdJwt.disclosures[0]
        assertNull(d.path, "Unmatched disclosure hash should leave path as null")
    }

    @Test
    fun `parse throws for disclosure with non-string salt`() {
        // Salt is a number instead of a string
        val badDisclosure = """[123, "name", "value"]"""
        val encodedBad =
                Base64.getUrlEncoder().withoutPadding().encodeToString(badDisclosure.toByteArray())
        val sdJwtString = "some.base.jwt~$encodedBad~"
        val result = parser.parse(sdJwtString)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IllegalArgumentException)
    }

    @Test
    fun `parse throws for disclosure with non-string claimName`() {
        // claimName is a number instead of a string
        val badDisclosure = """["salt", 42, "value"]"""
        val encodedBad =
                Base64.getUrlEncoder().withoutPadding().encodeToString(badDisclosure.toByteArray())
        val sdJwtString = "some.base.jwt~$encodedBad~"
        val result = parser.parse(sdJwtString)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IllegalArgumentException)
    }
}

