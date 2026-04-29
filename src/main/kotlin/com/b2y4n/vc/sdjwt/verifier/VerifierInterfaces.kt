package com.b2y4n.vc.sdjwt.verifier

/**
 * Abstraction for verifying the cryptographic signature of a parsed JWT string.
 *
 * Separates signature verification logic from the orchestration in [SdJwtVerifier],
 * allowing different cryptographic backends (e.g., Nimbus JOSE+JWT, BouncyCastle) to
 * be injected without modifying the verification pipeline.
 *
 * @see SignatureVerifierImpl
 * @see SdJwtVerifier
 */
interface SignatureVerifier {
    /**
     * Verifies that the cryptographic signature on the provided JWT is valid.
     *
     * @param jwt The Base64url-encoded JWT string in JWS compact serialization
     *            format (`Header.Payload.Signature`).
     * @return A [Result] wrapping `true` if the signature is mathematically valid,
     *         `false` if the signature does not match, or a failure exception if
     *         parsing or verification definitively fails.
     */
    fun verify(jwt: String): Result<Boolean>
}

/**
 * Abstraction for verifying Key Binding JWTs during SD-JWT presentation validation.
 *
 * Key Binding verification ensures that the presenter possesses the private key
 * corresponding to the public key embedded in the `cnf` claim of the base JWT,
 * as defined in [RFC 9901 Section 7](https://www.rfc-editor.org/rfc/rfc9901.html#section-7).
 *
 * @see KeyBindingVerifierImpl
 * @see SdJwtVerifier
 */
interface KeyBindingVerifier {
    /**
     * Verifies the Key Binding JWT according to the context of the SD-JWT presentation.
     *
     * Implementations must validate:
     * - The `typ` header is `"kb+jwt"`.
     * - The signature matches the public key from the `cnf.jwk` claim in the base JWT.
     * - The `aud` claim matches the expected audience (typically the verifier's URI).
     * - The `nonce` claim matches the challenge issued by the verifier.
     * - The `iat` claim is within an acceptable time window.
     * - The `sd_hash` claim matches the SHA-256 hash of the presentation string (without the KB-JWT).
     *
     * @param kbJwt The Key Binding JWT string to verify.
     * @param baseJwtPayload The decoded base JWT payload JSON string containing the `cnf` claim
     *                       with the holder's public key.
     * @param presentationString The SD-JWT presentation string excluding the KB-JWT portion,
     *                           used to compute and validate the `sd_hash` binding.
     * @return A [Result] wrapping `true` if all Key Binding checks pass, `false` otherwise,
     *         or a failure exception if validation definitively fails.
     */
    fun verifyKeyBinding(kbJwt: String, baseJwtPayload: String, presentationString: String): Result<Boolean>
}
