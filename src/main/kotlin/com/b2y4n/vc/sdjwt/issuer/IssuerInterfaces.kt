package com.b2y4n.vc.sdjwt.issuer

import kotlinx.serialization.json.JsonObject


/**
 * Abstraction for generating cryptographic salts used in SD-JWT disclosure creation.
 *
 * Implementations must produce salts with sufficient entropy to prevent brute-force
 * reversal of disclosure hashes. RFC 9901 recommends a minimum of 128 bits of entropy.
 *
 * @see com.b2y4n.vc.sdjwt.issuer.PayloadConcealer
 */
interface SaltGenerator {
    /**
     * Generates a sufficiently random, URL-safe string to be used as a salt in a disclosure.
     *
     * The generated salt is embedded as the first element of the disclosure JSON array
     * (e.g., `["salt", "claim_name", "claim_value"]`) and must not be predictable.
     *
     * @return A URL-safe random string with at least 128 bits of entropy, as recommended
     *         by RFC 9901 Section 5.2.
     */
    fun generateSalt(): String
}

/**
 * Abstraction for signing the underlying JWT during SD-JWT issuance.
 *
 * Inverts the dependency on specific cryptographic libraries (e.g., Nimbus JOSE+JWT)
 * by allowing any JWS-compliant signer to be injected into [SdJwtIssuer].
 *
 * @see SdJwtIssuer
 */
interface JwtSigner {
    /**
     * The JWS algorithm identifier (e.g., `"ES256"`, `"RS256"`) used for signing.
     *
     * This value is automatically embedded into the JWS header `alg` field when no
     * explicit header is provided to [SdJwtIssuer.issue].
     */
    val algorithm: String

    /**
     * Signs the given header and payload, producing a complete JWS compact serialization string.
     *
     * @param header The JSON object representing the JWS header, containing at minimum `alg` and `typ`.
     * @param payload The JSON object representing the JWT payload with `_sd` and `_sd_alg` claims embedded.
     * @return The signed JWT string in JWS compact serialization format (`header.payload.signature`).
     */
    fun sign(header: JsonObject, payload: JsonObject): String
}
