package com.b2y4n.vc.sdjwt.models

/**
 * Represents a parsed Selective Disclosure JWT (SD-JWT) as defined in
 * [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html).
 *
 * An SD-JWT is composed of a base JWT, zero or more [Disclosure] objects revealing
 * selectively disclosable claims, and an optional Key Binding JWT proving holder
 * possession of the private key corresponding to the `cnf` claim.
 *
 * The serialized format follows the `~`-delimited structure:
 * `<jwt>~<disclosure_1>~...~<disclosure_n>~[<kb_jwt>]`
 *
 * @property jwt The base JWT string in JWS compact serialization format
 *               (`Header.Payload.Signature`).
 * @property disclosures A list of decoded [Disclosure] objects parsed from the SD-JWT string.
 * @property kbJwt The optional Key Binding JWT string, if present. Used to prove holder possession
 *                 of the private key corresponding to the `cnf` claim in the base JWT.
 */
data class SdJwt(
    val jwt: String,
    val disclosures: List<Disclosure> = emptyList(),
    val kbJwt: String? = null
) {
    /**
     * Returns the serialized SD-JWT string in the standard `~`-delimited format:
     * `<jwt>~<disclosure_1>~<disclosure_2>~...~<disclosure_n>~[<kb_jwt>]`
     *
     * If no disclosures are present, the result is `<jwt>~`. If a Key Binding JWT is present, it is
     * appended after the trailing `~`.
     *
     * @return The complete serialized SD-JWT string.
     */
    override fun toString(): String {
        val encodedDisclosures = disclosures.joinToString("~") { it.encoded }
        val disclosurePart = if (encodedDisclosures.isNotEmpty()) "~$encodedDisclosures~" else "~"
        val kbPart = kbJwt ?: ""
        return "$jwt$disclosurePart$kbPart"
    }
}
