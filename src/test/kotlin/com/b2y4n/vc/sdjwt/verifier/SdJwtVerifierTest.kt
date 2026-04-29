package com.b2y4n.vc.sdjwt.verifier

import java.security.MessageDigest
import java.util.Base64
import kotlin.test.*
import kotlin.test.Test
import kotlinx.serialization.json.*
import com.b2y4n.vc.sdjwt.models.SdJwtConstants

class SdJwtVerifierTest {

    private val staticSignatureVerifier =
            object : SignatureVerifier {
                override fun verify(jwt: String): Result<Boolean> {
                    return Result.success(jwt.endsWith(".signature"))
                }
            }

    private val staticKeyBindingVerifier =
            object : KeyBindingVerifier {
                override fun verifyKeyBinding(
                        kbJwt: String,
                        baseJwtPayload: String,
                        presentationString: String
                ): Result<Boolean> {
                    return Result.success(kbJwt == "kbjwt" && baseJwtPayload.contains(SdJwtConstants.CLAIM_CNF))
                }
            }

    private val verifier =
            SdJwtVerifier(
                    parser = com.b2y4n.vc.sdjwt.parser.SdJwtParser(),
                    signatureVerifier = staticSignatureVerifier,
                    keyBindingVerifier = staticKeyBindingVerifier
            )

    @Test
    fun `verify successful reconstruction`() {
        val disclosureStr = """["salt123", "email", "john@example.com"]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())

        val digest = MessageDigest.getInstance("SHA-256")
        val hashStr =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                digest.digest(encodedDisclosure.toByteArray(Charsets.US_ASCII))
                        )

        val payload = buildJsonObject {
            put("iss", "example.com")
            put(SdJwtConstants.CLAIM_SD_ALG, "sha-256")
            put(SdJwtConstants.CLAIM_SD, JsonArray(listOf(JsonPrimitive(hashStr))))
        }
        val pEnc =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.toString().toByteArray())
        val baseJwt = "header.$pEnc.signature"

        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = verifier.verify(sdJwtString)

        assertTrue(result.isSuccess)
        val reconstructed = result.getOrThrow()

        assertEquals("example.com", reconstructed["iss"]?.jsonPrimitive?.content)
        assertEquals("john@example.com", reconstructed["email"]?.jsonPrimitive?.content)
        assertTrue(SdJwtConstants.CLAIM_SD !in reconstructed)
        assertTrue(SdJwtConstants.CLAIM_SD_ALG !in reconstructed)
    }

    @Test
    fun `verify throws if hash mismatch`() {
        val disclosureStr = """["salt123", "email", "john@example.com"]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())

        val payload = buildJsonObject {
            put(SdJwtConstants.CLAIM_SD_ALG, "sha-256")
            put(SdJwtConstants.CLAIM_SD, JsonArray(listOf(JsonPrimitive("invalidhash"))))
        }
        val pEnc =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.toString().toByteArray())
        val baseJwt = "header.$pEnc.signature"
        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = verifier.verify(sdJwtString)
        assertTrue(result.isFailure)
        assertEquals(result.exceptionOrNull()?.message?.contains("unused or unmatched"), true)
    }

    @Test
    fun `verify throws if base signature fails`() {
        val disclosureStr = """["salt", "key", "val"]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())

        val payload = buildJsonObject { put(SdJwtConstants.CLAIM_SD_ALG, "sha-256") }
        val pEnc =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.toString().toByteArray())
        val baseJwt = "header.$pEnc.invalid" // fails the dumb signature check
        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = verifier.verify(sdJwtString)
        assertTrue(result.isFailure)
        assertEquals(
            result.exceptionOrNull()
                ?.message
                ?.contains("Base JWT signature verification failed"), true
        )
    }

    @Test
    fun `verify throws if kb jwt signature fails`() {
        val payload = buildJsonObject { put("test", "test") }
        val pEnc =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.toString().toByteArray())
        val baseJwt = "header.$pEnc.signature"
        val sdJwtString = "$baseJwt~badkbjwt"

        val result = verifier.verify(sdJwtString)
        assertTrue(result.isFailure)
        assertEquals(result.exceptionOrNull()?.message?.contains("Key Binding JWT"), true)
    }

    @Test
    fun `verify recursive and structured reconstruction`() {
        // Disclosure 1 (nested object property)
        val d1Str = """["salt1", "city", "Berlin"]"""
        val d1Enc = Base64.getUrlEncoder().withoutPadding().encodeToString(d1Str.toByteArray())
        val d1Hash =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(d1Enc.toByteArray(Charsets.US_ASCII))
                        )

        // Disclosure 2 (top object property whose value is an object containing _sd)
        val addressValue = """{"_sd": ["$d1Hash"]}"""
        val d2Str = """["salt2", "address", $addressValue]"""
        val d2Enc = Base64.getUrlEncoder().withoutPadding().encodeToString(d2Str.toByteArray())
        val d2Hash =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(d2Enc.toByteArray(Charsets.US_ASCII))
                        )

        // Disclosure 3 (array element)
        val d3Str = """["salt3", "DE"]"""
        val d3Enc = Base64.getUrlEncoder().withoutPadding().encodeToString(d3Str.toByteArray())
        val d3Hash =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(d3Enc.toByteArray(Charsets.US_ASCII))
                        )

        val payload = buildJsonObject {
            put("iss", "example.com")
            put(SdJwtConstants.CLAIM_SD_ALG, "sha-256")
            put(SdJwtConstants.CLAIM_SD, JsonArray(listOf(JsonPrimitive(d2Hash))))
            put(
                    "nationalities",
                    JsonArray(listOf(JsonPrimitive("US"), buildJsonObject { put(SdJwtConstants.ARRAY_DECOY_KEY, d3Hash) }))
            )
        }

        val pEnc =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.toString().toByteArray())
        val baseJwt = "header.$pEnc.signature"
        val sdJwtString = "$baseJwt~$d1Enc~$d2Enc~$d3Enc~"

        val result = verifier.verify(sdJwtString)
        assertTrue(result.isSuccess)
        val reconstructed = result.getOrThrow()

        // Validate top level
        assertEquals("example.com", reconstructed["iss"]?.jsonPrimitive?.content)

        // Validate object recursive reconstruction
        val addressObj = reconstructed["address"]?.jsonObject
        assertNotNull(addressObj)
        assertEquals("Berlin", addressObj["city"]?.jsonPrimitive?.content)
        assertTrue(SdJwtConstants.CLAIM_SD !in addressObj)

        // Validate array element reconstruction
        val nationalitiesArray = reconstructed["nationalities"]?.jsonArray
        assertNotNull(nationalitiesArray)
        assertEquals(2, nationalitiesArray.size)
        assertEquals("US", nationalitiesArray[0].jsonPrimitive.content)
        assertEquals("DE", nationalitiesArray[1].jsonPrimitive.content)
    }

    @Test
    fun `verify fails when _sd_alg does not match configured hasher`() {
        val disclosureStr = """["salt123", "email", "john@example.com"]"""
        val encodedDisclosure =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureStr.toByteArray())

        val digest = MessageDigest.getInstance("SHA-256")
        val hashStr =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                digest.digest(encodedDisclosure.toByteArray(Charsets.US_ASCII))
                        )

        val payload = buildJsonObject {
            put(SdJwtConstants.CLAIM_SD_ALG, "sha-512") // Mismatch!
            put(SdJwtConstants.CLAIM_SD, JsonArray(listOf(JsonPrimitive(hashStr))))
        }
        val pEnc =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.toString().toByteArray())
        val baseJwt = "header.$pEnc.signature"
        val sdJwtString = "$baseJwt~$encodedDisclosure~"

        val result = verifier.verify(sdJwtString)
        assertTrue(result.isFailure)
        assertEquals(result.exceptionOrNull()?.message?.contains("Unsupported _sd_alg"), true)
    }

    @Test
    fun `verify fails when kb-jwt is present but no KeyBindingVerifier provided`() {
        val payload = buildJsonObject { put("test", "test") }
        val pEnc =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.toString().toByteArray())
        val baseJwt = "header.$pEnc.signature"
        // Append a KB-JWT to the presentation
        val sdJwtString = "$baseJwt~some.kb.jwt"

        // Create verifier WITHOUT a KeyBindingVerifier
        val verifierNoKb = SdJwtVerifier(
                parser = com.b2y4n.vc.sdjwt.parser.SdJwtParser(),
                signatureVerifier = staticSignatureVerifier,
                keyBindingVerifier = null
        )

        val result = verifierNoKb.verify(sdJwtString)
        assertTrue(result.isFailure)
        assertEquals(result.exceptionOrNull()?.message?.contains("no KeyBindingVerifier provided"), true)
    }
}

