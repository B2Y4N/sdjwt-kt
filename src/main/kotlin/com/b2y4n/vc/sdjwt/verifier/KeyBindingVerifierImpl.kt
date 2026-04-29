package com.b2y4n.vc.sdjwt.verifier

import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.security.MessageDigest
import java.util.Base64
import com.b2y4n.vc.sdjwt.models.SdJwtConstants

/**
 * Default RFC 9901 compliant implementation of [KeyBindingVerifier].
 *
 * Validates a Key Binding JWT by performing the following checks in order:
 * 1. **Header type**: The `typ` header must be `"kb+jwt"`.
 * 2. **Public key extraction**: Extracts the holder's public key from the `cnf.jwk` claim
 *    in the base JWT payload.
 * 3. **Signature verification**: Verifies the KB-JWT signature using the extracted public key
 *    and the Nimbus [DefaultJWSVerifierFactory].
 * 4. **Claims validation**: Validates `aud`, `nonce`, and `iat` claims against expected values.
 * 5. **Presentation binding**: Computes the SHA-256 hash of the presentation string
 *    (without the KB-JWT) and compares it to the `sd_hash` claim.
 *
 * @property expectedAudience The `aud` value expected in the KB-JWT payload, typically the
 *                            verifier's own URI or identifier.
 * @property expectedNonce The `nonce` value challenged by the verifier and expected in the
 *                         KB-JWT payload for replay protection.
 * @property maxAgeSeconds The maximum permitted age in seconds of the KB-JWT since its `iat`
 *                         timestamp. Defaults to `300` (5 minutes).
 * @constructor Creates a [KeyBindingVerifierImpl] with the specified audience, nonce, and
 *              maximum age constraints.
 */
class KeyBindingVerifierImpl(
    private val expectedAudience: String,
    private val expectedNonce: String,
    private val maxAgeSeconds: Long = 300
) : KeyBindingVerifier {

    /**
     * Verifies the Key Binding JWT against the embedded `cnf` payload from the base JWT.
     *
     * Performs all five verification steps (header type, key extraction, signature,
     * claims validation, and `sd_hash` binding) sequentially. If any step fails, the
     * corresponding [IllegalArgumentException] is wrapped in the returned [Result].
     *
     * A 60-second clock skew tolerance is applied to the `iat` freshness check.
     *
     * @param kbJwt The Key Binding JWT string to verify.
     * @param baseJwtPayload The decoded base JWT payload JSON string containing the `cnf`
     *                       claim with the holder's public key.
     * @param presentationString The SD-JWT presentation string excluding the KB-JWT portion,
     *                           used to compute the `sd_hash` digest for binding verification.
     * @return A [Result] wrapping `true` if all verification checks pass, or a failure
     *         exception describing the first check that failed.
     */
    override fun verifyKeyBinding(
        kbJwt: String,
        baseJwtPayload: String,
        presentationString: String
    ): Result<Boolean> = runCatching {
        
        val signedKbJwt = SignedJWT.parse(kbJwt)
        
        // 1. Verify Header `typ`
        val typ = signedKbJwt.header.type?.type
        require(typ == SdJwtConstants.HEADER_TYP_KB_JWT) { "Key Binding JWT header 'typ' must be 'kb+jwt'" }

        // 2. Extract public key from `cnf` in base JWT
        val basePayloadJson = Json.parseToJsonElement(baseJwtPayload).jsonObject
        val cnf = basePayloadJson[SdJwtConstants.CLAIM_CNF]?.jsonObject
            ?: throw IllegalArgumentException("Base JWT payload missing 'cnf' claim for Key Binding")
        val jwkObj = cnf[SdJwtConstants.CLAIM_JWK]?.jsonObject
            ?: throw IllegalArgumentException("Base JWT 'cnf' claim missing 'jwk'")

        // Convert kotlinx.serialization JsonObject to Nimbus JWK
        val jwkString = jwkObj.toString()
        val jwk = JWK.parse(jwkString)

        require(jwk is AsymmetricJWK) { "Key Binding JWK must be an asymmetric key" }

        // Find the right verifier based on JWK type (RSA, EC, OKP)
        val jwsVerifier = DefaultJWSVerifierFactory().createJWSVerifier(signedKbJwt.header, jwk.toPublicKey())
        
        // 3. Verify Signature
        require(signedKbJwt.verify(jwsVerifier)) { "Key Binding JWT signature is invalid" }

        // 4. Validate Claims
        val claimsContext = signedKbJwt.jwtClaimsSet

        // Verify `aud`
        val aud = claimsContext.audience
        require(!aud.isNullOrEmpty()) { "Key Binding JWT missing 'aud' claim" }
        require(aud.contains(expectedAudience)) { "Key Binding JWT audience does not match expected" }

        // Verify `nonce`
        val nonce = claimsContext.getStringClaim(SdJwtConstants.CLAIM_NONCE)
        require(nonce == expectedNonce) { "Key Binding JWT nonce does not match expected" }

        // Verify `iat`
        val iat = claimsContext.issueTime
        requireNotNull(iat) { "Key Binding JWT must contain 'iat' claim" }
        
        val currentTimeMs = System.currentTimeMillis()
        val iatMs = iat.time
        require(currentTimeMs >= iatMs - 60000) { "Key Binding JWT 'iat' is in the future" } // allow 60s clock skew
        require(currentTimeMs - iatMs <= maxAgeSeconds * 1000) { "Key Binding JWT is too old or expired" }

        // 5. Verify `sd_hash`
        val sdHashClaim = claimsContext.getStringClaim(SdJwtConstants.CLAIM_SD_HASH)
        requireNotNull(sdHashClaim) { "Key Binding JWT must contain 'sd_hash' claim" }

        // The hashing algorithm is implicitly SHA-256 for standard cases.
        // Hashing the presentation string (minus the ~KB_JWT).
        val digest = MessageDigest.getInstance("SHA-256")
        val computedHashBytes = digest.digest(presentationString.toByteArray(Charsets.US_ASCII))
        val computedHashString = Base64.getUrlEncoder().withoutPadding().encodeToString(computedHashBytes)

        require(sdHashClaim == computedHashString) { "Key Binding JWT 'sd_hash' does not match presentation digest" }

        true
    }
}
