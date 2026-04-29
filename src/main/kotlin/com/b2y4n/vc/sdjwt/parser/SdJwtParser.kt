package com.b2y4n.vc.sdjwt.parser

import com.b2y4n.vc.sdjwt.crypto.Hasher
import com.b2y4n.vc.sdjwt.crypto.Sha256Hasher
import com.b2y4n.vc.sdjwt.models.Disclosure
import com.b2y4n.vc.sdjwt.models.SdJwt
import com.b2y4n.vc.sdjwt.models.SdJwtConstants
import com.b2y4n.vc.sdjwt.models.ClaimPath
import java.util.Base64
import kotlinx.serialization.json.*

/**
 * Parses an SD-JWT string into its structural components: the base JWT, decoded
 * [Disclosure] objects, and an optional Key Binding JWT.
 *
 * This class performs **structural parsing only** — it does not verify cryptographic
 * signatures or validate claims. Signature and claim verification are delegated to
 * [com.b2y4n.vc.sdjwt.verifier.SdJwtVerifier], adhering to the Single Responsibility Principle.
 *
 * The parser:
 * 1. Splits the `~`-delimited string into JWT, disclosure, and KB-JWT segments.
 * 2. Decodes each disclosure from Base64url into a [Disclosure] domain object.
 * 3. Resolves structural [ClaimPath] mappings by traversing the JWT payload and
 *    matching disclosure hashes against `_sd` arrays and `...` array decoy keys.
 * 4. Constructs an [SdJwt] instance with the resolved disclosures and optional KB-JWT.
 *
 * @property json The [Json] instance used for JSON deserialization. Defaults to a lenient
 *                configuration that ignores unknown keys.
 * @property hasher The [Hasher] used to compute disclosure digest hashes for path resolution.
 *                  Defaults to [Sha256Hasher].
 * @constructor Creates an [SdJwtParser] with the specified JSON and hashing configuration.
 */
class SdJwtParser(
        private val json: Json = Json { ignoreUnknownKeys = true },
        private val hasher: Hasher = Sha256Hasher()
) {

    /**
     * Parses the given SD-JWT string representation into a structured [SdJwt] domain model.
     *
     * The input string must follow the SD-JWT serialization format:
     * `<base_jwt>~<disclosure_1>~...~<disclosure_n>~[<kb_jwt>]`
     *
     * @param sdJwtString The `~`-delimited SD-JWT string to parse.
     * @return A [Result] containing the [SdJwt] domain model (with resolved [ClaimPath]
     *         mappings on each disclosure) if parsing succeeds, or a failure exception
     *         if the input is malformed.
     * @throws IllegalArgumentException (wrapped in [Result]) if the string is blank, the
     *         base JWT is malformed, or any disclosure is not valid Base64url or JSON.
     */
    fun parse(sdJwtString: String): Result<SdJwt> = runCatching {
        require(sdJwtString.isNotBlank()) { "SD-JWT string cannot be blank" }

        val parts = sdJwtString.split("~")
        require(parts.isNotEmpty()) { "Invalid SD-JWT format" }

        // The first part is ALWAYS the base JWT
        val baseJwt = parts[0]
        require(baseJwt.count { it == '.' } == 2) { "Base JWT is malformed" }

        // The last part is the Key Binding JWT, which can be empty
        // According to SD-JWT serialization format:
        // <base_jwt>~<disclosure_1>~...~<disclosure_n>~<kb_jwt?>
        // So the last element is kb_jwt. If there are no disclosures and no kb_jwt, it's just
        // <base_jwt>~
        val kbJwtRaw = parts.last()
        val kbJwt = kbJwtRaw.takeIf { it.isNotBlank() }

        // The middle parts are disclosures
        val disclosuresRaw =
                if (parts.size > 2) {
                    parts.subList(1, parts.size - 1)
                } else {
                    emptyList()
                }

        val disclosures = disclosuresRaw.map { parseDisclosure(it) }

        val payloadStr =
                String(Base64.getUrlDecoder().decode(baseJwt.split(".")[1]), Charsets.UTF_8)
        val payload = json.parseToJsonElement(payloadStr)

        val disclosureMap = disclosures.associateBy { hasher.hashBase64Url(it.encoded) }

        val mappedPaths = mutableMapOf<String, ClaimPath>()
        extractPaths(payload, ClaimPath.root, disclosureMap, mappedPaths)

        val finalDisclosures =
                disclosures.map {
                    val hashStr = hasher.hashBase64Url(it.encoded)
                    it.copy(path = mappedPaths[hashStr])
                }

        SdJwt(jwt = baseJwt, disclosures = finalDisclosures, kbJwt = kbJwt)
    }

    /**
     * Recursively traverses the JWT payload to resolve [ClaimPath] mappings for each
     * disclosure by matching digest hashes against `_sd` arrays and `...` array decoy keys.
     *
     * For JSON objects, the method:
     * - Recurses into non-reserved properties (`_sd`, `_sd_alg` are skipped).
     * - Iterates over the `_sd` array to match disclosure hashes and assign [ClaimPath]s.
     *
     * For JSON arrays, the method:
     * - Identifies `{"...": "<hash>"}` decoy wrappers and resolves their disclosure paths.
     * - Recurses into non-decoy array elements.
     *
     * Disclosures that do not match any hash in the payload are silently ignored
     * (their path remains unresolved).
     *
     * @param element The current [JsonElement] being traversed.
     * @param currentPath The [ClaimPath] of the current traversal position.
     * @param disclosureMap A hash-to-[Disclosure] lookup map for O(1) matching.
     * @param mappedPaths The mutable output map from disclosure hash to resolved [ClaimPath].
     */
    private fun extractPaths(
            element: JsonElement,
            currentPath: ClaimPath,
            disclosureMap: Map<String, Disclosure>,
            mappedPaths: MutableMap<String, ClaimPath>
    ) {
        if (element is JsonObject) {
            for ((key, value) in element) {
                if (key == SdJwtConstants.CLAIM_SD || key == SdJwtConstants.CLAIM_SD_ALG) continue
                val newPath = currentPath.claim(key)
                extractPaths(value, newPath, disclosureMap, mappedPaths)
            }

            element[SdJwtConstants.CLAIM_SD]?.let { sdNode ->
                if (sdNode is JsonArray) {
                    sdNode.forEach { hashElement ->
                        if (hashElement is JsonPrimitive) {
                            val hash = hashElement.content
                            val disclosure = disclosureMap[hash] ?: return@forEach
                            val claimName = disclosure.claimName ?: return@forEach
                            val newPath = currentPath.claim(claimName)
                            mappedPaths[hash] = newPath
                            extractPaths(disclosure.claimValue, newPath, disclosureMap, mappedPaths)
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
                        mappedPaths[hash] = newPath
                        extractPaths(disclosure.claimValue, newPath, disclosureMap, mappedPaths)
                    }
                } else {
                    extractPaths(item, newPath, disclosureMap, mappedPaths)
                }
            }
        }
    }

    /**
     * Decodes and parses a single Base64url-encoded disclosure string into a [Disclosure]
     * domain object.
     *
     * Determines the disclosure type based on the JSON array length:
     * - **2 elements** (`[salt, claimValue]`): An array element disclosure.
     * - **3 elements** (`[salt, claimName, claimValue]`): An object property disclosure.
     *
     * @param encoded The Base64url-encoded disclosure string (without padding).
     * @return The parsed [Disclosure] with `encoded`, `salt`, `claimName` (nullable), and
     *         `claimValue` fields populated. The `path` field is left `null` at this stage.
     * @throws IllegalArgumentException if the string is not valid Base64url, not a valid
     *         JSON array, has an unexpected element count, or contains invalid salt/claimName types.
     */
    private fun parseDisclosure(encoded: String): Disclosure {
        val decodedBytes =
                runCatching { Base64.getUrlDecoder().decode(encoded) }.getOrElse {
                    throw IllegalArgumentException(
                            "Disclosure is not valid Base64url: $encoded",
                            it
                    )
                }

        val decodedString = String(decodedBytes, Charsets.UTF_8)
        val jsonArray =
                runCatching { json.parseToJsonElement(decodedString) as JsonArray }.getOrElse {
                    throw IllegalArgumentException(
                            "Disclosure is not a valid JSON array: $decodedString",
                            it
                    )
                }

        return when (jsonArray.size) {
            2 -> {
                // Array element disclosure: [salt, claimValue]
                val salt =
                        (jsonArray[0] as? JsonPrimitive)?.content
                                ?: throw IllegalArgumentException("Invalid salt in disclosure")
                val claimValue = jsonArray[1]

                Disclosure(
                        encoded = encoded,
                        salt = salt,
                        claimName = null,
                        claimValue = claimValue
                )
            }
            3 -> {
                // Object property disclosure: [salt, claimName, claimValue]
                val salt =
                        (jsonArray[0] as? JsonPrimitive)?.content
                                ?: throw IllegalArgumentException("Invalid salt in disclosure")
                val claimName =
                        (jsonArray[1] as? JsonPrimitive)?.content
                                ?: throw IllegalArgumentException("Invalid claimName in disclosure")
                val claimValue = jsonArray[2]

                Disclosure(
                        encoded = encoded,
                        salt = salt,
                        claimName = claimName,
                        claimValue = claimValue
                )
            }
            else ->
                    throw IllegalArgumentException(
                            "Disclosure JSON array must have 2 or 3 elements, found: ${jsonArray.size}"
                    )
        }
    }
}
