package com.b2y4n.vc.sdjwt.models

import kotlinx.serialization.json.JsonElement

/**
 * Represents a single decoded Disclosure in an SD-JWT as defined in
 * [RFC 9901 Section 5.2](https://www.rfc-editor.org/rfc/rfc9901.html#section-5.2).
 *
 * A disclosure is a Base64url-encoded JSON array that reveals the original claim
 * value when presented by the holder. Two structural variants exist:
 *
 * - **Object property disclosure** (3 elements): `[salt, claimName, claimValue]` — reveals a
 *   named key-value pair that was replaced by a digest in the `_sd` array.
 * - **Array element disclosure** (2 elements): `[salt, claimValue]` — reveals an array item
 *   that was replaced by `{"...": "<digest>"}` in the concealed array.
 *
 * Equality and hash code are determined solely by the [encoded] string, since the same
 * Base64url encoding uniquely identifies a disclosure regardless of parsed content.
 *
 * @property encoded The original Base64url-encoded string of the disclosure (without padding).
 * @property salt The random salt used to prevent brute-force reversal of the disclosure hash.
 * @property claimName The name of the disclosed claim. `null` if this disclosure represents an
 *                     array element rather than an object property.
 * @property claimValue The value of the disclosed claim, represented as a [JsonElement].
 *                      Can be a primitive, JSON object, or JSON array.
 * @property path The structural [ClaimPath] indicating where this disclosure maps within the
 *               payload tree. `null` if the disclosure was parsed without structural context
 *               (e.g., prior to path resolution).
 */
data class Disclosure(
    val encoded: String,
    val salt: String,
    val claimName: String?,
    val claimValue: JsonElement,
    val path: ClaimPath? = null
) {
    /**
     * Compares this disclosure to [other] based solely on the [encoded] string.
     *
     * Two disclosures are considered equal if and only if their Base64url-encoded
     * representations are identical, regardless of any differences in parsed fields.
     *
     * @param other The object to compare against.
     * @return `true` if [other] is a [Disclosure] with the same [encoded] value; `false` otherwise.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Disclosure) return false
        return encoded == other.encoded
    }

    /**
     * Returns a hash code derived solely from the [encoded] string.
     *
     * @return The hash code of [encoded].
     */
    override fun hashCode(): Int {
        return encoded.hashCode()
    }
}
