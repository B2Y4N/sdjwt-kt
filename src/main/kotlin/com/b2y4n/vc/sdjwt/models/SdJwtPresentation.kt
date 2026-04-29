package com.b2y4n.vc.sdjwt.models

/**
 * Represents an SD-JWT Presentation created by a holder for a verifier.
 *
 * A presentation wraps an [SdJwt] containing the original base JWT, a subset of
 * disclosures the holder chose to reveal, and optionally a Key Binding JWT proving
 * possession of the holder's private key. It is kept as a distinct wrapper type to
 * clearly separate the presentation context from the full issued SD-JWT.
 *
 * The serialized format follows the same `~`-delimited structure as [SdJwt]:
 * `<jwt>~<disclosure_1>~...~<disclosure_n>~[<kb_jwt>]`
 *
 * @property sdJwt The underlying [SdJwt] containing the base JWT, selected disclosures,
 *                 and optional Key Binding JWT.
 * @see com.b2y4n.vc.sdjwt.presenter.SdJwtPresenter
 * @see com.b2y4n.vc.sdjwt.verifier.SdJwtVerifier
 */
data class SdJwtPresentation(
    val sdJwt: SdJwt
) {
    /**
     * Returns the serialized SD-JWT presentation string in the standard `~`-delimited format.
     *
     * @return The full presentation string including the base JWT, selected disclosures,
     *         and optional Key Binding JWT.
     */
    override fun toString(): String = sdJwt.toString()
}
