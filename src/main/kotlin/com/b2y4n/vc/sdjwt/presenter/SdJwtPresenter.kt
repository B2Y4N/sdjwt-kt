package com.b2y4n.vc.sdjwt.presenter

import com.b2y4n.vc.sdjwt.crypto.Hasher
import com.b2y4n.vc.sdjwt.crypto.Sha256Hasher
import com.b2y4n.vc.sdjwt.models.Disclosure
import com.b2y4n.vc.sdjwt.models.SdJwt
import com.b2y4n.vc.sdjwt.models.SdJwtConstants
import com.b2y4n.vc.sdjwt.models.SdJwtPresentation
import com.b2y4n.vc.sdjwt.models.ClaimPath
import com.b2y4n.vc.sdjwt.utils.SystemTimeProvider
import com.b2y4n.vc.sdjwt.utils.TimeProvider
import java.util.Base64
import kotlinx.serialization.json.*

/**
 * Abstraction for generating Key Binding JWTs during SD-JWT presentation creation.
 *
 * A Key Binding JWT proves that the presenter holds the private key corresponding
 * to the public key embedded in the `cnf` claim of the base JWT, as defined in
 * [RFC 9901 Section 7](https://www.rfc-editor.org/rfc/rfc9901.html#section-7).
 *
 * @see SdJwtPresenter
 */
interface KbJwtSigner {
    /**
     * Signs the Key Binding JWT payload and returns the complete JWT string.
     *
     * Implementations must include `typ: "kb+jwt"` in the JWS header as required by
     * [SdJwtConstants.HEADER_TYP_KB_JWT].
     *
     * @param payload The [JsonObject] containing the KB-JWT claims (`nonce`, `aud`, `iat`, `sd_hash`).
     * @return The signed Key Binding JWT string in JWS compact serialization format.
     */
    fun sign(payload: JsonObject): String
}

/**
 * Creates SD-JWT presentations by selectively disclosing a subset of claims from
 * an issued SD-JWT and optionally generating a Key Binding JWT.
 *
 * The presenter operates as a fluent builder:
 * 1. Select claim paths to disclose via [select].
 * 2. Optionally configure Key Binding via [kbSigner], [aud], and [nonce].
 * 3. Build the final [SdJwtPresentation] via [build].
 *
 * The selection logic traverses the JWT payload tree, matching `_sd` digest arrays and
 * `...` array decoy keys against the user-selected [ClaimPath]s. Ancestor and descendant
 * path relationships are honored (e.g., selecting `address` automatically discloses
 * `address.street` if it is a nested disclosure).
 *
 * Example usage:
 * ```kotlin
 * val presentation = SdJwtPresenter(issuedSdJwt)
 *     .select(ClaimPath.claim("name"))
 *     .select(ClaimPath.root.claim("address").claim("city"))
 *     .kbSigner(myKbSigner)
 *     .aud("https://verifier.example")
 *     .nonce("abc123")
 *     .build()
 * ```
 *
 * @property issuedSdJwt The parsed [SdJwt] from which to derive the presentation.
 * @property hasher The [Hasher] used to compute disclosure digest hashes and the `sd_hash` for
 *                  Key Binding. Defaults to [Sha256Hasher].
 * @property timeProvider The [TimeProvider] used to generate the `iat` timestamp for Key Binding
 *                        JWTs. Defaults to [SystemTimeProvider].
 * @constructor Creates an [SdJwtPresenter] for the given issued SD-JWT.
 */
class SdJwtPresenter(
        private val issuedSdJwt: SdJwt,
        private val hasher: Hasher = Sha256Hasher(),
        private val timeProvider: TimeProvider = SystemTimeProvider()
) {
    private val selectedPaths = mutableSetOf<ClaimPath>()
    private var kbSigner: KbJwtSigner? = null
    private var aud: String? = null
    private var nonce: String? = null

    /**
     * Selects a claim path to be disclosed in the presentation.
     *
     * Multiple paths can be selected by chaining calls. Path relationships are
     * honored — selecting a parent path automatically includes all nested child
     * disclosures beneath it.
     *
     * @param path The [ClaimPath] identifying the claim to disclose.
     * @return This presenter for fluent chaining.
     */
    fun select(path: ClaimPath): SdJwtPresenter {
        selectedPaths.add(path)
        return this
    }

    /**
     * Configures the Key Binding JWT signer for the presentation.
     *
     * When set, the [build] method will generate and append a Key Binding JWT
     * to the presentation. Requires [aud] and [nonce] to also be configured.
     *
     * @param kbSigner The [KbJwtSigner] used to sign the Key Binding JWT.
     * @return This presenter for fluent chaining.
     */
    fun kbSigner(kbSigner: KbJwtSigner): SdJwtPresenter {
        this.kbSigner = kbSigner
        return this
    }

    /**
     * Configures the audience claim for the Key Binding JWT.
     *
     * Typically the verifier's URI or identifier. Required when a [kbSigner] is configured.
     *
     * @param aud The expected audience value for the Key Binding JWT `aud` claim.
     * @return This presenter for fluent chaining.
     */
    fun aud(aud: String): SdJwtPresenter {
        this.aud = aud
        return this
    }

    /**
     * Configures the nonce claim for the Key Binding JWT.
     *
     * A challenge value issued by the verifier for replay protection. Required when
     * a [kbSigner] is configured.
     *
     * @param nonce The nonce value for the Key Binding JWT `nonce` claim.
     * @return This presenter for fluent chaining.
     */
    fun nonce(nonce: String): SdJwtPresenter {
        this.nonce = nonce
        return this
    }

    /**
     * Builds an [SdJwtPresentation] containing only the selected disclosures and
     * optionally a Key Binding JWT.
     *
     * The build process:
     * 1. Traverses the base JWT payload to identify which disclosures match the selected
     *    [ClaimPath]s (including ancestor/descendant relationships).
     * 2. If a [kbSigner] is configured, generates a Key Binding JWT containing `nonce`,
     *    `aud`, `iat`, and the `sd_hash` of the presentation string (without the KB-JWT).
     * 3. Wraps the result as an [SdJwtPresentation].
     *
     * @return The derived [SdJwtPresentation] containing the base JWT, selected disclosures,
     *         and optional Key Binding JWT.
     * @throws IllegalArgumentException if [kbSigner] is set but [aud] or [nonce] is `null`.
     */
    fun build(): SdJwtPresentation {

        val payloadStr =
                String(Base64.getUrlDecoder().decode(issuedSdJwt.jwt.split(".")[1]), Charsets.UTF_8)
        val basePayload = Json.parseToJsonElement(payloadStr)

        val disclosureMap = issuedSdJwt.disclosures.associateBy { hasher.hashBase64Url(it.encoded) }

        val resultDisclosures = mutableSetOf<Disclosure>()
        selectDisclosures(basePayload, ClaimPath.root, selectedPaths, disclosureMap, resultDisclosures)
        val selectedDisclosures = resultDisclosures.toList()

        // Generate KB-JWT if requested
        val kbJwt =
                kbSigner?.let { signer ->
                    requireNotNull(aud) { "Audience (aud) is required to generate a KB-JWT" }
                    requireNotNull(nonce) { "Nonce (nonce) is required to generate a KB-JWT" }

                    val iat = timeProvider.currentEpochSecond()

                    // Build the presentation string without KB-JWT to compute the sd_hash
                    val encodedDisclosures = selectedDisclosures.joinToString("~") { it.encoded }
                    val presentationWithoutKb =
                            if (encodedDisclosures.isNotEmpty()) {
                                "${issuedSdJwt.jwt}~$encodedDisclosures~"
                            } else {
                                "${issuedSdJwt.jwt}~"
                            }

                    val sdHashStr = hasher.hashBase64Url(presentationWithoutKb)

                    val kbPayload = buildJsonObject {
                        put(SdJwtConstants.CLAIM_NONCE, JsonPrimitive(nonce))
                        put("aud", JsonPrimitive(aud))
                        put("iat", JsonPrimitive(iat))
                        put(SdJwtConstants.CLAIM_SD_HASH, JsonPrimitive(sdHashStr))
                    }
                    signer.sign(kbPayload)
                }

        val presentationSdJwt =
                SdJwt(
                        jwt = issuedSdJwt.jwt,
                        disclosures = selectedDisclosures,
                        kbJwt = kbJwt
                )

        return SdJwtPresentation(presentationSdJwt)
    }

    /**
     * Recursively traverses the base JWT payload tree to collect disclosures whose
     * [ClaimPath]s match the user-selected paths.
     *
     * For JSON objects, the method:
     * - Recurses into non-reserved properties (skipping `_sd` and `_sd_alg`).
     * - Iterates over `_sd` digest arrays, checking if each disclosure's resolved path
     *   satisfies [isPathRequired] against the [selectedPaths].
     *
     * For JSON arrays, the method:
     * - Identifies `{"...": "<hash>"}` decoy wrappers and checks their resolved paths.
     * - Recurses into non-decoy array elements.
     *
     * Matching disclosures are added to [result] with their [ClaimPath] set. Duplicate
     * additions are prevented by the [MutableSet] contract.
     *
     * @param element The current [JsonElement] being traversed.
     * @param currentPath The [ClaimPath] of the current traversal position.
     * @param selectedPaths The user-selected paths to disclose.
     * @param disclosureMap A hash-to-[Disclosure] lookup map for O(1) matching.
     * @param result The mutable set accumulating matched disclosures.
     */
    private fun selectDisclosures(
            element: JsonElement,
            currentPath: ClaimPath,
            selectedPaths: Set<ClaimPath>,
            disclosureMap: Map<String, Disclosure>,
            result: MutableSet<Disclosure>
    ) {
        if (element is JsonObject) {
            for ((key, value) in element) {
                if (key == SdJwtConstants.CLAIM_SD || key == SdJwtConstants.CLAIM_SD_ALG) continue
                val newPath = currentPath.claim(key)
                selectDisclosures(value, newPath, selectedPaths, disclosureMap, result)
            }

            element[SdJwtConstants.CLAIM_SD]?.let { sdNode ->
                if (sdNode is JsonArray) {
                    sdNode.forEach { hashElement ->
                        if (hashElement is JsonPrimitive) {
                            val hash = hashElement.content
                            val disclosure = disclosureMap[hash] ?: return@forEach
                            val claimName = disclosure.claimName ?: return@forEach
                            val newPath = currentPath.claim(claimName)

                            if (isPathRequired(newPath, selectedPaths)) {
                                val disclosureWithPath = disclosure.copy(path = newPath)
                                if (result.add(disclosureWithPath)) {
                                    selectDisclosures(
                                            disclosure.claimValue,
                                            newPath,
                                            selectedPaths,
                                            disclosureMap,
                                            result
                                    )
                                }
                            }
                        }
                    }
                }
            }
        } else if (element is JsonArray) {
            element.forEachIndexed { index, item ->
                val newPath = currentPath.arrayElement(index)
                if (item is JsonObject &&
                                item.keys.size == 1 &&
                                item.containsKey(SdJwtConstants.ARRAY_DECOY_KEY)
                ) {
                    val hashParam = item[SdJwtConstants.ARRAY_DECOY_KEY]
                    if (hashParam is JsonPrimitive) {
                        val hash = hashParam.content
                        val disclosure = disclosureMap[hash] ?: return@forEachIndexed
                        if (isPathRequired(newPath, selectedPaths)) {
                            val disclosureWithPath = disclosure.copy(path = newPath)
                            if (result.add(disclosureWithPath)) {
                                selectDisclosures(
                                        disclosure.claimValue,
                                        newPath,
                                        selectedPaths,
                                        disclosureMap,
                                        result
                                )
                            }
                        }
                    }
                } else {
                    selectDisclosures(item, newPath, selectedPaths, disclosureMap, result)
                }
            }
        }
    }

    /**
     * Determines whether a given [ClaimPath] should be included in the presentation
     * based on the user-selected paths.
     *
     * A path is considered required if:
     * - It exactly matches a selected path, **or**
     * - It is a descendant of a selected path (the user selected a parent, so all
     *   children are implicitly included), **or**
     * - It is an ancestor of a selected path (a nested child was selected, so the
     *   parent disclosure must be included to make the child accessible).
     *
     * @param path The [ClaimPath] to evaluate.
     * @param selectedPaths The set of user-selected [ClaimPath]s.
     * @return `true` if [path] should be included in the presentation; `false` otherwise.
     */
    private fun isPathRequired(path: ClaimPath, selectedPaths: Set<ClaimPath>): Boolean {
        for (selected in selectedPaths) {
            if (path.isSubPathOf(selected) || selected.isSubPathOf(path)) return true
        }
        return false
    }
}
