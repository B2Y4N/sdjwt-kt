package com.b2y4n.vc.sdjwt.verifier

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.security.MessageDigest
import java.util.Base64
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertTrue
import com.b2y4n.vc.sdjwt.models.SdJwtConstants
import kotlin.test.assertEquals

class KeyBindingVerifierImplTest {

    private val ecKey: ECKey = ECKeyGenerator(Curve.P_256).keyID("123").generate()
    private val expectedAudience = "https://verifier.example.com"
    private val expectedNonce = "random_nonce_123"

    private val verifier = KeyBindingVerifierImpl(expectedAudience, expectedNonce, 300)

    private fun computeSdHash(presentation: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val computedHashBytes = digest.digest(presentation.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(computedHashBytes)
    }

    @Test
    fun `verify success with valid KB-JWT`() {
        val presentationString = "header.payload.sig~disclosure1~disclosure2~"
        val sdHash = computeSdHash(presentationString)

        val claims =
                JWTClaimsSet.Builder()
                        .audience(expectedAudience)
                        .claim(SdJwtConstants.CLAIM_NONCE, expectedNonce)
                        .issueTime(Date())
                        .claim(SdJwtConstants.CLAIM_SD_HASH, sdHash)
                        .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType(SdJwtConstants.HEADER_TYP_KB_JWT)).build()
        val kbJwt = SignedJWT(header, claims)
        kbJwt.sign(ECDSASigner(ecKey))

        val jwkPubStr = ecKey.toPublicJWK().toJSONString()
        val basePayload = """{"cnf": {"jwk": $jwkPubStr}}"""

        val result = verifier.verifyKeyBinding(kbJwt.serialize(), basePayload, presentationString)

        assertTrue(result.isSuccess)
        assertTrue(result.getOrThrow())
    }

    @Test
    fun `verify fails with missing aud`() {
        val presentationString = "header.payload~"
        val claims =
                JWTClaimsSet.Builder()
                        .claim(SdJwtConstants.CLAIM_NONCE, expectedNonce)
                        .issueTime(Date())
                        .claim(SdJwtConstants.CLAIM_SD_HASH, computeSdHash(presentationString))
                        .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType(SdJwtConstants.HEADER_TYP_KB_JWT)).build()
        val kbJwt = SignedJWT(header, claims)
        kbJwt.sign(ECDSASigner(ecKey))

        val basePayload = """{"cnf": {"jwk": ${ecKey.toPublicJWK().toJSONString()}}}"""
        val result = verifier.verifyKeyBinding(kbJwt.serialize(), basePayload, presentationString)

        assertTrue(result.isFailure)
        assertEquals(result.exceptionOrNull()?.message?.contains("missing 'aud'"), true)
    }

    @Test
    fun `verify fails with wrong nonce`() {
        val presentationString = "header.payload~"
        val claims =
                JWTClaimsSet.Builder()
                        .audience(expectedAudience)
                        .claim(SdJwtConstants.CLAIM_NONCE, "bad_nonce")
                        .issueTime(Date())
                        .claim(SdJwtConstants.CLAIM_SD_HASH, computeSdHash(presentationString))
                        .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType(SdJwtConstants.HEADER_TYP_KB_JWT)).build()
        val kbJwt = SignedJWT(header, claims)
        kbJwt.sign(ECDSASigner(ecKey))

        val basePayload = """{"cnf": {"jwk": ${ecKey.toPublicJWK().toJSONString()}}}"""
        val result = verifier.verifyKeyBinding(kbJwt.serialize(), basePayload, presentationString)

        assertTrue(result.isFailure)
        assertEquals(result.exceptionOrNull()?.message?.contains("nonce does not match expected"), true)
    }

    @Test
    fun `verify fails with incorrect header typ`() {
        val presentationString = "header.payload~"
        val claims =
                JWTClaimsSet.Builder()
                        .audience(expectedAudience)
                        .claim(SdJwtConstants.CLAIM_NONCE, expectedNonce)
                        .issueTime(Date())
                        .claim(SdJwtConstants.CLAIM_SD_HASH, computeSdHash(presentationString))
                        .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build()
        val kbJwt = SignedJWT(header, claims)
        kbJwt.sign(ECDSASigner(ecKey))

        val basePayload = """{"cnf": {"jwk": ${ecKey.toPublicJWK().toJSONString()}}}"""
        val result = verifier.verifyKeyBinding(kbJwt.serialize(), basePayload, presentationString)

        assertTrue(result.isFailure)
        assertEquals(result.exceptionOrNull()?.message?.contains("'typ' must be 'kb+jwt'"), true)
    }

    @Test
    fun `verify fails with bad sd_hash`() {
        val presentationString = "header.payload.sig~disclosure1~"
        val claims =
                JWTClaimsSet.Builder()
                        .audience(expectedAudience)
                        .claim(SdJwtConstants.CLAIM_NONCE, expectedNonce)
                        .issueTime(Date())
                        .claim(SdJwtConstants.CLAIM_SD_HASH, "wrong_hash")
                        .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType(SdJwtConstants.HEADER_TYP_KB_JWT)).build()
        val kbJwt = SignedJWT(header, claims)
        kbJwt.sign(ECDSASigner(ecKey))

        val basePayload = """{"cnf": {"jwk": ${ecKey.toPublicJWK().toJSONString()}}}"""
        val result = verifier.verifyKeyBinding(kbJwt.serialize(), basePayload, presentationString)

        assertTrue(result.isFailure)
        assertEquals(result.exceptionOrNull()?.message?.contains(SdJwtConstants.CLAIM_SD_HASH), true)
    }

    @Test
    fun `verify fails when iat is too old beyond maxAgeSeconds`() {
        val presentationString = "header.payload.sig~disclosure1~"
        val sdHash = computeSdHash(presentationString)

        // Set iat to 10 minutes ago (600 seconds), but maxAge is 300 seconds
        val oldIat = Date(System.currentTimeMillis() - 600_000)
        val claims =
                JWTClaimsSet.Builder()
                        .audience(expectedAudience)
                        .claim(SdJwtConstants.CLAIM_NONCE, expectedNonce)
                        .issueTime(oldIat)
                        .claim(SdJwtConstants.CLAIM_SD_HASH, sdHash)
                        .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType(SdJwtConstants.HEADER_TYP_KB_JWT)).build()
        val kbJwt = SignedJWT(header, claims)
        kbJwt.sign(ECDSASigner(ecKey))

        val basePayload = """{"cnf": {"jwk": ${ecKey.toPublicJWK().toJSONString()}}}"""
        val result = verifier.verifyKeyBinding(kbJwt.serialize(), basePayload, presentationString)

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()?.message?.contains("too old or expired") == true)
    }

    @Test
    fun `verify fails when iat is far in the future beyond clock skew tolerance`() {
        val presentationString = "header.payload.sig~disclosure1~"
        val sdHash = computeSdHash(presentationString)

        // Set iat to 5 minutes in the future (well beyond 60s clock skew tolerance)
        val futureIat = Date(System.currentTimeMillis() + 300_000)
        val claims =
                JWTClaimsSet.Builder()
                        .audience(expectedAudience)
                        .claim(SdJwtConstants.CLAIM_NONCE, expectedNonce)
                        .issueTime(futureIat)
                        .claim(SdJwtConstants.CLAIM_SD_HASH, sdHash)
                        .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType(SdJwtConstants.HEADER_TYP_KB_JWT)).build()
        val kbJwt = SignedJWT(header, claims)
        kbJwt.sign(ECDSASigner(ecKey))

        val basePayload = """{"cnf": {"jwk": ${ecKey.toPublicJWK().toJSONString()}}}"""
        val result = verifier.verifyKeyBinding(kbJwt.serialize(), basePayload, presentationString)

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()?.message?.contains("in the future") == true)
    }

    @Test
    fun `verify fails when base payload is missing cnf claim`() {
        val presentationString = "header.payload.sig~"
        val sdHash = computeSdHash(presentationString)

        val claims =
                JWTClaimsSet.Builder()
                        .audience(expectedAudience)
                        .claim(SdJwtConstants.CLAIM_NONCE, expectedNonce)
                        .issueTime(Date())
                        .claim(SdJwtConstants.CLAIM_SD_HASH, sdHash)
                        .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType(SdJwtConstants.HEADER_TYP_KB_JWT)).build()
        val kbJwt = SignedJWT(header, claims)
        kbJwt.sign(ECDSASigner(ecKey))

        // Base payload WITHOUT cnf claim
        val basePayload = """{"iss": "example.com"}"""
        val result = verifier.verifyKeyBinding(kbJwt.serialize(), basePayload, presentationString)

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()?.message?.contains("missing 'cnf'") == true)
    }

    @Test
    fun `verify fails when cnf claim is missing jwk`() {
        val presentationString = "header.payload.sig~"
        val sdHash = computeSdHash(presentationString)

        val claims =
                JWTClaimsSet.Builder()
                        .audience(expectedAudience)
                        .claim(SdJwtConstants.CLAIM_NONCE, expectedNonce)
                        .issueTime(Date())
                        .claim(SdJwtConstants.CLAIM_SD_HASH, sdHash)
                        .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType(SdJwtConstants.HEADER_TYP_KB_JWT)).build()
        val kbJwt = SignedJWT(header, claims)
        kbJwt.sign(ECDSASigner(ecKey))

        // cnf present but missing jwk key
        val basePayload = """{"cnf": {"kid": "some-key-id"}}"""
        val result = verifier.verifyKeyBinding(kbJwt.serialize(), basePayload, presentationString)

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()?.message?.contains("missing 'jwk'") == true)
    }
}

