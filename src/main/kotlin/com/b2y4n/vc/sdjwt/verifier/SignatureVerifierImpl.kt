package com.b2y4n.vc.sdjwt.verifier

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jwt.SignedJWT

/**
 * Standard implementation of [SignatureVerifier] leveraging the Nimbus JOSE+JWT library.
 *
 * Parses the raw JWT string into a [SignedJWT] and delegates cryptographic signature
 * verification to the provided [JWSVerifier] instance, which encapsulates the
 * algorithm-specific verification key (e.g., RSA, EC, OKP).
 *
 * @property jwsVerifier The Nimbus [JWSVerifier] used to cryptographically validate
 *                       the JWT signature. Must match the algorithm and key used during signing.
 * @constructor Creates an instance with the specified [JWSVerifier].
 */
class SignatureVerifierImpl(
    private val jwsVerifier: JWSVerifier
) : SignatureVerifier {

    /**
     * Parses the JWT string into a [SignedJWT] and verifies the signature using the
     * injected [JWSVerifier].
     *
     * @param jwt The Base64url-encoded JWT string in JWS compact serialization
     *            format (`Header.Payload.Signature`). Must not be blank.
     * @return A [Result] wrapping `true` if the signature is valid, `false` if the
     *         signature does not match, or a failure if the JWT cannot be parsed.
     * @throws IllegalArgumentException if [jwt] is blank.
     */
    override fun verify(jwt: String): Result<Boolean> = runCatching {
        require(jwt.isNotBlank()) { "JWT string cannot be blank" }
        
        val signedJWT = SignedJWT.parse(jwt)
        signedJWT.verify(jwsVerifier)
    }
}
