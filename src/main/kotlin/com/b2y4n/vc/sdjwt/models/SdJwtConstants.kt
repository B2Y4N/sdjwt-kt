package com.b2y4n.vc.sdjwt.models

/**
 * Centralized constants for the SD-JWT specification as defined in
 * [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html).
 *
 * Contains reserved claim names, header type identifiers, and the set of security-critical
 * claims that must never be made selectively disclosable at the root level per
 * RFC 9901 Section 9.7.
 */
object SdJwtConstants {
    /** The `_sd` claim key holding the array of disclosure digests within a JSON object. */
    const val CLAIM_SD = "_sd"

    /** The `_sd_alg` claim key identifying the hash algorithm used for disclosure digests. */
    const val CLAIM_SD_ALG = "_sd_alg"

    /** The `...` key used in concealed array elements to hold the disclosure digest. */
    const val ARRAY_DECOY_KEY = "..."

    /** The `sd_hash` claim key in the Key Binding JWT payload, binding it to the presentation. */
    const val CLAIM_SD_HASH = "sd_hash"

    /** The `cnf` (confirmation) claim key in the base JWT payload, embedding the holder's public key. */
    const val CLAIM_CNF = "cnf"

    /** The `nonce` claim key used in Key Binding JWT payloads for replay protection. */
    const val CLAIM_NONCE = "nonce"

    /** The `jwk` key within the `cnf` claim, containing the holder's JSON Web Key. */
    const val CLAIM_JWK = "jwk"

    /** The JWS header `typ` value for Key Binding JWTs: `"kb+jwt"`. */
    const val HEADER_TYP_KB_JWT = "kb+jwt"

    /** The JWS header `typ` value for SD-JWTs: `"sd-jwt"`. */
    const val HEADER_TYP_SD_JWT = "sd-jwt"

    /**
     * The set of security-critical claims that must NOT be made selectively disclosable
     * at the root level of an SD-JWT payload, as mandated by RFC 9901 Section 9.7.
     *
     * Concealing these claims would undermine the security guarantees of the token
     * (e.g., issuer identity, expiration, holder binding).
     */
    val SECURITY_CRITICAL_CLAIMS = setOf("iss", "exp", "nbf", "iat", "sub", "vct", CLAIM_CNF)
}
