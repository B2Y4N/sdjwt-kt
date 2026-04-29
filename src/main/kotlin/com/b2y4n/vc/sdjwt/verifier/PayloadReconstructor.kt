package com.b2y4n.vc.sdjwt.verifier

import com.b2y4n.vc.sdjwt.models.Disclosure
import kotlinx.serialization.json.*
import com.b2y4n.vc.sdjwt.models.SdJwtConstants

/**
 * Responsible for recursively reconstructing the clear-text SD-JWT payload by resolving
 * `_sd` digest arrays and `...` array decoy keys with their corresponding disclosure values.
 *
 * During reconstruction, the class tracks which disclosure hashes were actually consumed
 * in [usedHashes]. After reconstruction, [SdJwtVerifier] compares this set against all
 * provided disclosures to detect unused — and therefore potentially malicious — disclosures
 * that must cause verification failure per RFC 9901.
 *
 * @property disclosureMap A hash-to-[Disclosure] lookup map providing O(1) access to decoded
 *                         disclosures by their Base64url digest hash.
 * @constructor Creates a [PayloadReconstructor] with the given disclosure lookup map.
 */
class PayloadReconstructor(private val disclosureMap: Map<String, Disclosure>) {
    /**
     * The set of disclosure hashes that were successfully matched and consumed during
     * reconstruction. Used by [SdJwtVerifier] to detect unused disclosures.
     */
    val usedHashes = mutableSetOf<String>()

    /**
     * Recursively reconstructs the clear-text JSON payload from a concealed [JsonElement].
     *
     * For [JsonObject]s, `_sd` digests are resolved to their disclosure values and merged
     * into the object. For [JsonArray]s, `{"...": "<hash>"}` wrappers are replaced by
     * the disclosed values. JSON primitives are returned unchanged.
     *
     * Consumed disclosure hashes are tracked in [usedHashes] for post-reconstruction
     * validation.
     *
     * @param element The concealed [JsonElement] to reconstruct. Can be a [JsonObject],
     *                [JsonArray], or JSON primitive.
     * @return The fully reconstructed clear-text [JsonElement] with all matched disclosures
     *         substituted in place.
     */
    fun reconstruct(element: JsonElement): JsonElement {
        return when (element) {
            is JsonObject -> reconstructObject(element)
            is JsonArray -> reconstructArray(element)
            else -> element
        }
    }

    /**
     * Reconstructs a JSON object by resolving its `_sd` digest array.
     *
     * For each hash in the `_sd` array:
     * - If a matching disclosure exists in [disclosureMap], the disclosure's `claimName` and
     *   `claimValue` are added to the reconstructed object (after recursively reconstructing
     *   the value).
     * - If no matching disclosure exists, the hash is treated as a decoy and skipped.
     *
     * The `_sd` and `_sd_alg` keys are stripped from the output.
     *
     * @param element The concealed [JsonObject] containing `_sd` digest arrays.
     * @return The reconstructed [JsonObject] with disclosed claims merged in.
     * @throws IllegalArgumentException if a disclosure in the `_sd` array is an array element
     *         disclosure (missing `claimName`), or if a claim name collision is detected.
     */
    private fun reconstructObject(element: JsonObject): JsonObject {
        val reconstructedMap = mutableMapOf<String, JsonElement>()
        val allowedHashes = element[SdJwtConstants.CLAIM_SD]?.jsonArray?.map { it.jsonPrimitive.content }?.toSet() ?: emptySet()

        for ((key, value) in element) {
            if (key == SdJwtConstants.CLAIM_SD || key == SdJwtConstants.CLAIM_SD_ALG) continue
            reconstructedMap[key] = reconstruct(value)
        }

        for (hash in allowedHashes) {
            val disclosure = disclosureMap[hash] ?: continue // Skip missing disclosures instead of throwing
            usedHashes.add(hash)

            require(disclosure.claimName != null) {
                "Found array element disclosure in object _sd array for hash $hash"
            }

            require(!reconstructedMap.containsKey(disclosure.claimName)) {
                "Claim name collision during reconstruction: ${disclosure.claimName}"
            }

            // Recursively reconstruct the disclosure's value
            reconstructedMap[disclosure.claimName] = reconstruct(disclosure.claimValue)
        }

        return JsonObject(reconstructedMap)
    }

    /**
     * Reconstructs a JSON array by resolving `{"...": "<hash>"}` array element wrappers.
     *
     * For each array item:
     * - If the item is a single-key object with the `...` key and a matching disclosure
     *   exists, the wrapper is replaced by the recursively reconstructed disclosure value.
     * - If the hash has no matching disclosure, the wrapper is treated as a decoy and omitted.
     * - Non-wrapper items are recursively reconstructed as-is.
     *
     * @param element The concealed [JsonArray] containing `...` digest wrappers.
     * @return The reconstructed [JsonArray] with disclosed elements substituted in.
     * @throws IllegalArgumentException if a disclosure matched in an array context is an
     *         object property disclosure (has a non-null `claimName`).
     */
    private fun reconstructArray(element: JsonArray): JsonArray {
        val reconstructedList = mutableListOf<JsonElement>()

        for (item in element) {
            if (item is JsonObject && item.keys.size == 1 && item.containsKey(SdJwtConstants.ARRAY_DECOY_KEY)) {
                val hash = item[SdJwtConstants.ARRAY_DECOY_KEY]?.jsonPrimitive?.content ?: continue
                val disclosure = disclosureMap[hash] ?: continue // Skip array hashes that weren't disclosed

                usedHashes.add(hash)

                require(disclosure.claimName == null) {
                    "Found object property disclosure in array for hash $hash"
                }

                // Recursively reconstruct the array disclosure's value
                reconstructedList.add(reconstruct(disclosure.claimValue))
            } else {
                reconstructedList.add(reconstruct(item))
            }
        }
        return JsonArray(reconstructedList)
    }
}
