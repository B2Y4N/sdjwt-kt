package com.b2y4n.vc.sdjwt.verifier

import com.b2y4n.vc.sdjwt.crypto.Hasher
import com.b2y4n.vc.sdjwt.crypto.Sha256Hasher
import com.b2y4n.vc.sdjwt.models.Disclosure
import com.b2y4n.vc.sdjwt.parser.SdJwtParser
import kotlinx.serialization.json.*
import java.util.Base64
import com.b2y4n.vc.sdjwt.models.SdJwtConstants

/**
 * Orchestrates the end-to-end verification of an SD-JWT Presentation as defined in
 * [RFC 9901 Section 8](https://www.rfc-editor.org/rfc/rfc9901.html#section-8).
 *
 * The verification pipeline:
 * 1. **Parse**: Delegates to [SdJwtParser] to split the presentation string into its
 *    structural components (base JWT, disclosures, optional KB-JWT).
 * 2. **Signature verification**: Validates the base JWT signature via [SignatureVerifier].
 * 3. **Key Binding verification** (optional): If a KB-JWT is present, validates it via
 *    [KeyBindingVerifier], checking audience, nonce, timing, signature, and `sd_hash` binding.
 * 4. **Disclosure verification and reconstruction**: Hashes each disclosure, matches digests
 *    against `_sd` arrays and `...` wrappers in the payload, and reconstructs the clear-text
 *    payload via [PayloadReconstructor]. **Any unused disclosures cause verification failure.**
 *
 * @property parser The [SdJwtParser] used to parse the raw SD-JWT string.
 * @property signatureVerifier The [SignatureVerifier] used to validate the base JWT signature.
 * @property hasher The [Hasher] used to compute disclosure digest hashes. Defaults to [Sha256Hasher].
 * @property keyBindingVerifier An optional [KeyBindingVerifier] for KB-JWT validation. If `null`
 *                              and a KB-JWT is present, verification fails.
 * @constructor Creates an [SdJwtVerifier] with the specified verification dependencies.
 */
class SdJwtVerifier(
    private val parser: SdJwtParser,
    private val signatureVerifier: SignatureVerifier,
    private val hasher: Hasher = Sha256Hasher(),
    private val keyBindingVerifier: KeyBindingVerifier? = null
) {

    /**
     * Verifies the given SD-JWT presentation string and reconstructs the clear-text payload.
     *
     * This is the primary public API for verification. The method returns the fully
     * reconstructed [JsonObject] on success, or a failure exception encapsulating the
     * specific verification error.
     *
     * @param sdJwtString The `~`-delimited SD-JWT presentation string to verify.
     * @return A [Result] containing the reconstructed clear-text [JsonObject] if all
     *         verification checks pass, or a failure exception if any step fails
     *         (parsing, signature, key binding, or unused disclosure detection).
     */
    fun verify(sdJwtString: String): Result<JsonObject> = runCatching {
        // 1. Parse the token
        val parsedSdJwt = parser.parse(sdJwtString).getOrThrow()

        // 2. Validate base JWT signature
        val isSignatureValid = signatureVerifier.verify(parsedSdJwt.jwt).getOrThrow()
        require(isSignatureValid) { "Base JWT signature verification failed" }

        // 3. Extract the base JWT payload (second part of Base64url encoded parts)
        val payloadStr = String(Base64.getUrlDecoder().decode(parsedSdJwt.jwt.split(".")[1]), Charsets.UTF_8)
        val basePayload = Json.parseToJsonElement(payloadStr).jsonObject

        // 4. Verify Key Binding JWT if present
        // Must be done before returning the reconstructed payload
        parsedSdJwt.kbJwt?.let { kbJwt ->
            requireNotNull(keyBindingVerifier) { "Key Binding JWT present, but no KeyBindingVerifier provided" }
            
            // Reconstruct the presentation string without the KB-JWT
            val presentationString = sdJwtString.substringBeforeLast("~") + "~"
            
            val isKbValid = keyBindingVerifier.verifyKeyBinding(kbJwt, payloadStr, presentationString).getOrThrow()
            require(isKbValid) { "Key Binding JWT verification failed" }
        }

        // 5. Verify hashes and reconstruct payload
        verifyHashesAndReconstruct(basePayload, parsedSdJwt.disclosures)
    }

    /**
     * Verifies all disclosure hashes against the base JWT payload and reconstructs
     * the clear-text payload.
     *
     * This method:
     * 1. Validates that the `_sd_alg` claim matches the configured [hasher] algorithm.
     * 2. Delegates reconstruction to [PayloadReconstructor].
     * 3. Asserts that **all** provided disclosures were consumed during reconstruction.
     *    Any unused disclosures indicate a malformed or malicious presentation and cause
     *    verification failure.
     *
     * @param basePayload The decoded base JWT payload as a [JsonObject].
     * @param disclosures The list of [Disclosure] objects parsed from the presentation.
     * @return The fully reconstructed clear-text [JsonObject].
     * @throws IllegalArgumentException if the `_sd_alg` does not match the configured hasher,
     *         or if unused disclosures are detected.
     */
    private fun verifyHashesAndReconstruct(basePayload: JsonObject, disclosures: List<Disclosure>): JsonObject {
        // Build a lookup map of hash -> disclosure for O(1) retrieval
        val disclosureMap = disclosures.associateBy {
            hasher.hashBase64Url(it.encoded)
        }

        val expectedAlg = basePayload[SdJwtConstants.CLAIM_SD_ALG]?.jsonPrimitive?.content ?: "sha-256"
        if (disclosures.isNotEmpty()) {
            require(expectedAlg.equals(hasher.algorithmName, ignoreCase = true)) {
                "Unsupported _sd_alg: $expectedAlg. Expected: ${hasher.algorithmName}."
            }
        }

        val reconstructor = PayloadReconstructor(disclosureMap)
        val reconstructed = reconstructor.reconstruct(basePayload) as JsonObject
        
        val unusedHashes = disclosureMap.keys - reconstructor.usedHashes
        require(unusedHashes.isEmpty()) { 
            "Verification failed: The presentation contains unused or unmatched disclosures" 
        }
        
        return reconstructed
    }
}
