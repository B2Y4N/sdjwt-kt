package com.b2y4n.vc.sdjwt.verifier

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SignatureVerifierImplTest {

    @Test
    fun `verify success with valid MAC signature`() {
        val secret = ByteArray(32)
        SecureRandom().nextBytes(secret)
        val signer = MACSigner(secret)
        val verifierNode = MACVerifier(secret)

        val claims = JWTClaimsSet.Builder().subject("test").build()
        val signedJWT = SignedJWT(JWSHeader(JWSAlgorithm.HS256), claims)
        signedJWT.sign(signer)

        val verifier = SignatureVerifierImpl(verifierNode)
        val result = verifier.verify(signedJWT.serialize())

        assertTrue(result.isSuccess)
        assertTrue(result.getOrThrow())
    }

    @Test
    fun `verify fails with invalid JWT format`() {
        val secret = ByteArray(32)
        val verifierNode = MACVerifier(secret)
        val verifier = SignatureVerifierImpl(verifierNode)

        val result = verifier.verify("invalid.format")
        assertTrue(result.isFailure)
    }

    @Test
    fun `verify returns false or throws with invalid signature secret`() {
        val secret1 = ByteArray(32)
        SecureRandom().nextBytes(secret1)
        val secret2 = ByteArray(32)
        SecureRandom().nextBytes(secret2)
        
        val signer = MACSigner(secret1)
        val verifierNode = MACVerifier(secret2)

        val claims = JWTClaimsSet.Builder().subject("test").build()
        val signedJWT = SignedJWT(JWSHeader(JWSAlgorithm.HS256), claims)
        signedJWT.sign(signer)

        val verifier = SignatureVerifierImpl(verifierNode)
        val result = verifier.verify(signedJWT.serialize())

        // Depending on Nimbus version, SignedJWT.verify with wrong MAC secret might return false,
        // or the MACVerifier might throw during verification. We just check if it fails or returns false.
        if (result.isSuccess) {
            assertFalse(result.getOrThrow())
        } else {
            assertTrue(result.isFailure)
        }
    }

    @Test
    fun `verify fails for blank JWT string`() {
        val secret = ByteArray(32)
        SecureRandom().nextBytes(secret)
        val verifierNode = MACVerifier(secret)
        val verifier = SignatureVerifierImpl(verifierNode)

        val result = verifier.verify("   ")
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IllegalArgumentException)
    }
}

