package com.b2y4n.vc.sdjwt.presenter

import com.b2y4n.vc.sdjwt.models.Disclosure
import com.b2y4n.vc.sdjwt.models.SdJwt
import com.b2y4n.vc.sdjwt.models.SdJwtConstants
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.*
import com.b2y4n.vc.sdjwt.models.ClaimPath
import kotlinx.serialization.json.*

class SdJwtPresenterTest {

    private fun computeHash(encoded: String): String {
        val hashBytes =
                MessageDigest.getInstance("SHA-256").digest(encoded.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes)
    }

    private val disclosureName = Disclosure("encName", "saltN", "name", JsonPrimitive("John"))
    private val disclosureEmail =
            Disclosure("encEmail", "saltE", "email", JsonPrimitive("test@test.com"))

    // Nested disclosure: address -> city
    private val disclosureCity = Disclosure("encCity", "saltC", "city", JsonPrimitive("NYC"))
    // Array disclosure: hobbies -> [0]
    private val disclosureHobby0 = Disclosure("encHobby0", "saltH0", null, JsonPrimitive("reading"))

    private fun createDummySdJwt(): SdJwt {
        val hashName = computeHash("encName")
        val hashEmail = computeHash("encEmail")
        val hashCity = computeHash("encCity")
        val hashHobby0 = computeHash("encHobby0")

        val payload = buildJsonObject {
            put(
                    SdJwtConstants.CLAIM_SD,
                    buildJsonArray {
                        add(hashName)
                        add(hashEmail)
                    }
            )
            put(
                    "address",
                    buildJsonObject {
                        put(SdJwtConstants.CLAIM_SD, buildJsonArray { add(hashCity) })
                    }
            )
            put(
                    "hobbies",
                    buildJsonArray {
                        add(buildJsonObject { put(SdJwtConstants.ARRAY_DECOY_KEY, hashHobby0) })
                        add(JsonPrimitive("swimming"))
                    }
            )
        }

        val payloadBase64 =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.toString().toByteArray())
        val jwt = "eyJhbGciOiJFUzI1NiJ9.$payloadBase64.signature"

        return SdJwt(
                jwt = jwt,
                disclosures =
                        listOf(disclosureName, disclosureEmail, disclosureCity, disclosureHobby0)
        )
    }

    @Test
    fun `present without kb-jwt filters disclosures using builder`() {
        val parsedSdJwt = createDummySdJwt()
        val presenter = SdJwtPresenter(parsedSdJwt)

        // Consent only to name
        val presentation = presenter.select(ClaimPath.claim("name")).build()

        assertEquals(1, presentation.sdJwt.disclosures.size)
        assertEquals("name", presentation.sdJwt.disclosures.first().claimName)
        assertNull(presentation.sdJwt.kbJwt)

        assertTrue(presentation.toString().contains("~encName~"))
        assertFalse(presentation.toString().contains("~encEmail~"))
    }

    @Test
    fun `presenter extracts nested object disclosure and intermediate disclosures if path selected`() {
        val parsedSdJwt = createDummySdJwt()
        val presenter = SdJwtPresenter(parsedSdJwt)

        val presentation = presenter.select(ClaimPath.claim("address").claim("city")).build()

        assertEquals(1, presentation.sdJwt.disclosures.size)
        // Note: here 'address' itself is not a disclosure in createDummySdJwt base disclosures,
        // it is just a plain object in the payload containing city's hash.
        val d = presentation.sdJwt.disclosures.find { it.claimName == "city" }
        assertNotNull(d)
        assertEquals("NYC", d.claimValue.jsonPrimitive.content)
    }

    @Test
    fun `presenter extracts specific array indices using bracket notation`() {
        val parsedSdJwt = createDummySdJwt()
        val presenter = SdJwtPresenter(parsedSdJwt)

        val presentation = presenter.select(ClaimPath.claim("hobbies").arrayElement(0)).build()

        assertEquals(1, presentation.sdJwt.disclosures.size)
        val d = presentation.sdJwt.disclosures.first()
        assertNull(d.claimName) // array elements have null claimName
        assertEquals("reading", d.claimValue.jsonPrimitive.content)
    }

    @Test
    fun `present with kb-jwt generates correct payload with sd_hash`() {
        var capturedKbPayload: String? = null

        val dummyKbSigner =
                object : KbJwtSigner {
                    override fun sign(payload: JsonObject): String {
                        capturedKbPayload = payload.toString()
                        return "header.base64payload.kbsig"
                    }
                }

        val parsedSdJwt = createDummySdJwt()
        val presenter = SdJwtPresenter(parsedSdJwt)

        val presentation =
                presenter
                        .select(ClaimPath.claim("name"))
                        .select(ClaimPath.claim("email"))
                        .kbSigner(dummyKbSigner)
                        .aud("https://verifier.example.com")
                        .nonce("123456")
                        .build()

        assertEquals(2, presentation.sdJwt.disclosures.size)
        assertEquals("header.base64payload.kbsig", presentation.sdJwt.kbJwt)

        assertNotNull(capturedKbPayload)
        assertTrue(capturedKbPayload.contains(""""aud":"https://verifier.example.com""""))
        assertTrue(capturedKbPayload.contains(""""nonce":"123456""""))
        assertTrue(capturedKbPayload.contains(""""sd_hash":""""))
        assertTrue(capturedKbPayload.contains("\"iat\":"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `present missing aud or nonce for kb-jwt throws Error`() {
        val dummyKbSigner =
                object : KbJwtSigner {
                    override fun sign(payload: JsonObject) = "sig"
                }

        val parsedSdJwt = createDummySdJwt()
        SdJwtPresenter(parsedSdJwt).kbSigner(dummyKbSigner).build()
    }

    @Test
    fun `presenter handles RFC 9901 A_1 structured object disclosures`() {
        val addressDisclosureArray =
                """["saltAddress", "address", {"locality":"NYC", "_sd":["hashLocality"]}]"""
        val addressEncoded =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(addressDisclosureArray.toByteArray())
        val hashAddress = computeHash(addressEncoded)

        val localityDisclosureArray = """["saltLocality", "locality", "Maxstadt"]"""
        val localityEncoded =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(localityDisclosureArray.toByteArray())
        val hashLocality = computeHash(localityEncoded)

        val payload = buildJsonObject {
            put(SdJwtConstants.CLAIM_SD, buildJsonArray { add(hashAddress) })
        }
        val payloadBase64 =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.toString().toByteArray())
        val jwt = "eyJhbGciOiJFUzI1NiJ9.$payloadBase64.signature"

        val disclosureAddress =
                Disclosure(
                        addressEncoded,
                        "saltAddress",
                        "address",
                        buildJsonObject {
                            put("locality", JsonPrimitive("NYC"))
                            put(
                                    SdJwtConstants.CLAIM_SD,
                                    buildJsonArray { add(JsonPrimitive(hashLocality)) }
                            )
                        }
                )
        val disclosureLocality =
                Disclosure(localityEncoded, "saltLocality", "locality", JsonPrimitive("Maxstadt"))

        val sdJwt = SdJwt(jwt, listOf(disclosureAddress, disclosureLocality))
        val presenter = SdJwtPresenter(sdJwt)

        val presentation1 = presenter.select(ClaimPath.claim("address")).build()
        assertEquals(
                2,
                presentation1.sdJwt.disclosures.size,
                "Selecting parent should recursively disclose nested disclosures"
        )

        // Reset presenter with the same parsing
        val presenter2 = SdJwtPresenter(sdJwt)
        val presentation2 = presenter2.select(ClaimPath.claim("address").claim("locality")).build()
        assertEquals(
                2,
                presentation2.sdJwt.disclosures.size,
                "Selecting child should disclose intermediate parents and the child"
        )
        assertTrue(presentation2.sdJwt.disclosures.any { it.claimName == "locality" })
    }

    @Test
    fun `presenter handles RFC 9901 A_2 structured array element disclosures`() {
        val elemDisclosureArray = """["saltHobby1", "swimming"]"""
        val elemEncoded =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(elemDisclosureArray.toByteArray())
        val hashElem = computeHash(elemEncoded)

        val hobbiesDisclosureArray =
                """["saltHobbies", "hobbies", ["reading", {"...": "$hashElem"}]]"""
        val hobbiesEncoded =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(hobbiesDisclosureArray.toByteArray())
        val hashHobbies = computeHash(hobbiesEncoded)

        val payload = buildJsonObject {
            put(SdJwtConstants.CLAIM_SD, buildJsonArray { add(hashHobbies) })
        }
        val payloadBase64 =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.toString().toByteArray())
        val jwt = "eyJhbGciOiJFUzI1NiJ9.$payloadBase64.signature"

        val disclosureHobbies =
                Disclosure(
                        hobbiesEncoded,
                        "saltHobbies",
                        "hobbies",
                        buildJsonArray {
                            add(JsonPrimitive("reading"))
                            add(
                                    buildJsonObject {
                                        put(SdJwtConstants.ARRAY_DECOY_KEY, JsonPrimitive(hashElem))
                                    }
                            )
                        }
                )
        val disclosureElem = Disclosure(elemEncoded, "saltHobby1", null, JsonPrimitive("swimming"))

        val sdJwt = SdJwt(jwt, listOf(disclosureHobbies, disclosureElem))
        val presenter = SdJwtPresenter(sdJwt)

        val presentation1 = presenter.select(ClaimPath.claim("hobbies").arrayElement(1)).build()
        assertEquals(
                2,
                presentation1.sdJwt.disclosures.size,
                "Should recursively disclose hobbies array and index 1"
        )
    }

    @Test
    fun `presenter with no selections produces empty disclosure list`() {
        val parsedSdJwt = createDummySdJwt()
        val presenter = SdJwtPresenter(parsedSdJwt)

        // Build without selecting anything
        val presentation = presenter.build()

        assertEquals(0, presentation.sdJwt.disclosures.size, "No selections should yield no disclosures")
        assertNull(presentation.sdJwt.kbJwt)
    }

    @Test
    fun `presenter selecting all top-level paths discloses all disclosures`() {
        val parsedSdJwt = createDummySdJwt()
        val presenter = SdJwtPresenter(parsedSdJwt)

        // Select everything: name, email (top-level _sd), address.city (nested _sd), hobbies[0] (array)
        val presentation = presenter
                .select(ClaimPath.claim("name"))
                .select(ClaimPath.claim("email"))
                .select(ClaimPath.claim("address").claim("city"))
                .select(ClaimPath.claim("hobbies").arrayElement(0))
                .build()

        assertEquals(4, presentation.sdJwt.disclosures.size, "All 4 disclosures should be included")
    }
}

