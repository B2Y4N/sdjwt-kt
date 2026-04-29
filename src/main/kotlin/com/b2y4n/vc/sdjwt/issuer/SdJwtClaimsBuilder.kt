package com.b2y4n.vc.sdjwt.issuer

import kotlinx.serialization.json.*
import com.b2y4n.vc.sdjwt.models.SdJwtConstants
import com.b2y4n.vc.sdjwt.models.ClaimPath

/**
 * Data transfer object representing the complete configuration for an SD-JWT issuance.
 *
 * Encapsulates the raw JSON payload, the set of claim paths to conceal, and the
 * decoy digest constraints. Instances are constructed exclusively via the [SdJwtClaims]
 * DSL factory function.
 *
 * @property payload The root [JsonObject] containing all claims (both cleartext and those
 *                   to be concealed).
 * @property fieldsToConceal An immutable set of [ClaimPath]s identifying which claims should
 *                           be replaced with disclosure digests during concealment.
 * @property decoyConstraints An immutable map from [ClaimPath] to the minimum number of
 *                            digests (real + decoy) required at that structural level.
 * @constructor Creates an [SdJwtClaims] instance. Internal visibility ensures construction
 *              only through the DSL builder.
 * @see SdJwtClaims
 */
class SdJwtClaims internal constructor(
    val payload: JsonObject,
    val fieldsToConceal: Set<ClaimPath>,
    val decoyConstraints: Map<ClaimPath, Int>
)

/**
 * Kotlin DSL entry point for building an [SdJwtClaims] configuration.
 *
 * Provides a fluent, idiomatic Kotlin builder pattern using a trailing lambda with
 * [SdJwtObjectBuilder] as the receiver scope. Claims are defined using methods like
 * [SdJwtObjectBuilder.claim], [SdJwtObjectBuilder.sdClaim], [SdJwtObjectBuilder.objClaim], etc.
 *
 * Example usage:
 * ```kotlin
 * val claims = SdJwtClaims(minimumDigests = 3) {
 *     claim("iss", "https://issuer.example")
 *     sdClaim("name", "John Doe")
 *     sdObjClaim("address") {
 *         sdClaim("street", "123 Main St")
 *         claim("country", "US")
 *     }
 * }
 * ```
 *
 * @param minimumDigests The minimum number of digests (real + decoy) to enforce at the
 *                       root level `_sd` array. Defaults to `0` (no decoy padding).
 * @param builderAction The DSL builder block executed within an [SdJwtObjectBuilder] scope.
 * @return A fully constructed [SdJwtClaims] instance ready for issuance.
 */
fun SdJwtClaims(minimumDigests: Int = 0, builderAction: SdJwtObjectBuilder.() -> Unit): SdJwtClaims {
    val rootPayload = mutableMapOf<String, JsonElement>()
    val fieldsToConceal = mutableSetOf<ClaimPath>()
    val decoyConstraints = mutableMapOf<ClaimPath, Int>().apply {
        if (minimumDigests > 0) put(ClaimPath.root, minimumDigests)
    }
    
    val builder = SdJwtObjectBuilder(ClaimPath.root, rootPayload, fieldsToConceal, decoyConstraints)
    builder.builderAction()
    
    return SdJwtClaims(JsonObject(rootPayload), fieldsToConceal.toSet(), decoyConstraints.toMap())
}

/**
 * Safely converts a JVM value to the corresponding [JsonElement].
 *
 * Supports [String], [Number], [Boolean], and existing [JsonElement] instances.
 * Throws [IllegalArgumentException] for unsupported types.
 *
 * @param value The value to convert.
 * @return The corresponding [JsonElement] representation.
 * @throws IllegalArgumentException if [value] is not a supported type.
 */
internal fun toJsonElementSafe(value: Any): JsonElement {
    return when (value) {
        is String -> JsonPrimitive(value)
        is Number -> JsonPrimitive(value)
        is Boolean -> JsonPrimitive(value)
        is JsonElement -> value
        else -> throw IllegalArgumentException("Unsupported type for SD-JWT claim: ${value::class.java.simpleName}")
    }
}

/**
 * Builder scope for defining claims within a JSON object in the SD-JWT DSL.
 *
 * Provides methods to add cleartext claims, selectively disclosable claims, nested
 * objects, and arrays at the current structural level. Enforces RFC 9901 Section 9.7
 * by rejecting attempts to make security-critical claims selectively disclosable
 * at the root level.
 *
 * @property currentPath The [ClaimPath] representing the current position in the JSON tree.
 * @property payloadMap The mutable map accumulating constructed JSON fields at this level.
 * @property fieldsToConceal The shared mutable set accumulating paths marked for concealment.
 * @property decoyConstraints The shared mutable map accumulating minimum decoy digest counts.
 * @constructor Creates a builder scoped to the given structural position.
 */
class SdJwtObjectBuilder(
    private val currentPath: ClaimPath,
    val payloadMap: MutableMap<String, JsonElement>,
    val fieldsToConceal: MutableSet<ClaimPath>,
    val decoyConstraints: MutableMap<ClaimPath, Int>
) {
    /**
     * Adds a cleartext claim that will **not** be selectively disclosable.
     *
     * The claim appears directly in the JWT payload without being replaced by a
     * disclosure digest.
     *
     * @param key The JSON property name.
     * @param value The claim value. Must be a [String], [Number], [Boolean], or [JsonElement].
     * @return This builder for fluent chaining.
     * @throws IllegalArgumentException if [value] is an unsupported type.
     */
    fun claim(key: String, value: Any): SdJwtObjectBuilder {
        payloadMap[key] = toJsonElementSafe(value)
        return this
    }

    /**
     * Adds a selectively disclosable (SD) claim.
     *
     * The key-value pair will be removed from the visible payload and replaced with
     * a disclosure digest in the `_sd` array. The original value is encoded as a
     * 3-element disclosure: `[salt, key, value]`.
     *
     * @param key The JSON property name to conceal.
     * @param value The claim value to conceal. Must be a [String], [Number], [Boolean], or [JsonElement].
     * @return This builder for fluent chaining.
     * @throws IllegalArgumentException if [key] is a security-critical claim at the root level
     *         (per RFC 9901 Section 9.7), or if [value] is an unsupported type.
     */
    fun sdClaim(key: String, value: Any): SdJwtObjectBuilder {
        require(!(currentPath is ClaimPath.Root && key in SdJwtConstants.SECURITY_CRITICAL_CLAIMS)) {
            "Security critical claim '$key' cannot be selectively disclosable (RFC 9901 Section 9.7)."
        }
        payloadMap[key] = toJsonElementSafe(value)
        val fullPath = currentPath.claim(key)
        fieldsToConceal.add(fullPath)
        return this
    }

    /**
     * Adds a cleartext nested JSON object claim.
     *
     * The object itself is visible in the payload, but its internal properties may
     * be individually concealed using the nested [builder] scope.
     *
     * @param key The JSON property name for the nested object.
     * @param minimumDigests The minimum number of digests (real + decoy) to enforce in
     *                       the nested object's `_sd` array. Defaults to `0`.
     * @param builder The nested [SdJwtObjectBuilder] block for defining child claims.
     * @return This builder for fluent chaining.
     */
    fun objClaim(key: String, minimumDigests: Int = 0, builder: SdJwtObjectBuilder.() -> Unit): SdJwtObjectBuilder {
        val fullPath = currentPath.claim(key)
        val childMap = mutableMapOf<String, JsonElement>()
        val childBuilder = SdJwtObjectBuilder(fullPath, childMap, fieldsToConceal, decoyConstraints)
        childBuilder.builder()
        payloadMap[key] = JsonObject(childMap)
        if (minimumDigests > 0) decoyConstraints[fullPath] = minimumDigests
        return this
    }

    /**
     * Adds a selectively disclosable nested JSON object claim.
     *
     * The entire object is concealed as a single disclosure, but its internal
     * properties may also be individually concealed using the nested [builder] scope,
     * enabling recursive selective disclosure.
     *
     * @param key The JSON property name for the nested object to conceal.
     * @param minimumDigests The minimum number of digests (real + decoy) to enforce in
     *                       the nested object's `_sd` array. Defaults to `0`.
     * @param builder The nested [SdJwtObjectBuilder] block for defining child claims.
     * @return This builder for fluent chaining.
     * @throws IllegalArgumentException if [key] is a security-critical claim at the root level.
     */
    fun sdObjClaim(key: String, minimumDigests: Int = 0, builder: SdJwtObjectBuilder.() -> Unit): SdJwtObjectBuilder {
        require(!(currentPath is ClaimPath.Root && key in SdJwtConstants.SECURITY_CRITICAL_CLAIMS)) {
            "Security critical claim '$key' cannot be selectively disclosable (RFC 9901 Section 9.7)."
        }
        val fullPath = currentPath.claim(key)
        val childMap = mutableMapOf<String, JsonElement>()
        val childBuilder = SdJwtObjectBuilder(fullPath, childMap, fieldsToConceal, decoyConstraints)
        childBuilder.builder()
        payloadMap[key] = JsonObject(childMap)
        fieldsToConceal.add(fullPath)
        if (minimumDigests > 0) decoyConstraints[fullPath] = minimumDigests
        return this
    }

    /**
     * Adds a cleartext JSON array claim.
     *
     * The array itself is visible in the payload, but individual elements may be
     * concealed using the nested [builder] scope.
     *
     * @param key The JSON property name for the array.
     * @param minimumDigests The minimum number of concealed element wrappers (real + decoy)
     *                       to enforce in the array. Defaults to `0`.
     * @param builder The nested [SdJwtArrayBuilder] block for defining array elements.
     * @return This builder for fluent chaining.
     */
    fun arrClaim(key: String, minimumDigests: Int = 0, builder: SdJwtArrayBuilder.() -> Unit): SdJwtObjectBuilder {
        val fullPath = currentPath.claim(key)
        val childList = mutableListOf<JsonElement>()
        val childBuilder = SdJwtArrayBuilder(fullPath, childList, fieldsToConceal, decoyConstraints)
        childBuilder.builder()
        payloadMap[key] = JsonArray(childList)
        if (minimumDigests > 0) decoyConstraints[fullPath] = minimumDigests
        return this
    }

    /**
     * Adds a selectively disclosable JSON array claim.
     *
     * The entire array is concealed as a single disclosure. Individual array elements
     * may also be individually concealed using the nested [builder] scope.
     *
     * @param key The JSON property name for the array to conceal.
     * @param minimumDigests The minimum number of concealed element wrappers (real + decoy)
     *                       to enforce in the array. Defaults to `0`.
     * @param builder The nested [SdJwtArrayBuilder] block for defining array elements.
     * @return This builder for fluent chaining.
     * @throws IllegalArgumentException if [key] is a security-critical claim at the root level.
     */
    fun sdArrClaim(key: String, minimumDigests: Int = 0, builder: SdJwtArrayBuilder.() -> Unit): SdJwtObjectBuilder {
        require(!(currentPath is ClaimPath.Root && key in SdJwtConstants.SECURITY_CRITICAL_CLAIMS)) {
            "Security critical claim '$key' cannot be selectively disclosable (RFC 9901 Section 9.7)."
        }
        val fullPath = currentPath.claim(key)
        val childList = mutableListOf<JsonElement>()
        val childBuilder = SdJwtArrayBuilder(fullPath, childList, fieldsToConceal, decoyConstraints)
        childBuilder.builder()
        payloadMap[key] = JsonArray(childList)
        fieldsToConceal.add(fullPath)
        if (minimumDigests > 0) decoyConstraints[fullPath] = minimumDigests
        return this
    }
}

/**
 * Builder scope for defining sequential elements within a JSON array in the SD-JWT DSL.
 *
 * Provides methods to add cleartext elements, selectively disclosable elements, and
 * nested objects as array items.
 *
 * @property currentPath The [ClaimPath] representing this array's position in the JSON tree.
 * @property arrayElements The mutable list accumulating constructed JSON elements.
 * @property fieldsToConceal The shared mutable set accumulating paths marked for concealment.
 * @property decoyConstraints The shared mutable map accumulating minimum decoy digest counts.
 * @constructor Creates a builder scoped to the given array position.
 */
class SdJwtArrayBuilder(
    private val currentPath: ClaimPath,
    val arrayElements: MutableList<JsonElement>,
    val fieldsToConceal: MutableSet<ClaimPath>,
    val decoyConstraints: MutableMap<ClaimPath, Int>
) {
    /**
     * Appends a cleartext element to the array.
     *
     * The element is visible directly in the JWT payload without concealment.
     *
     * @param value The element value. Must be a [String], [Number], [Boolean], or [JsonElement].
     * @return This builder for fluent chaining.
     * @throws IllegalArgumentException if [value] is an unsupported type.
     */
    fun claim(value: Any): SdJwtArrayBuilder {
        arrayElements.add(toJsonElementSafe(value))
        return this
    }

    /**
     * Appends a selectively disclosable element to the array.
     *
     * The element will be replaced in the concealed array by a `{"...": "<digest>"}`
     * wrapper object. The original value is encoded as a 2-element disclosure: `[salt, value]`.
     *
     * @param value The element value to conceal. Must be a [String], [Number], [Boolean], or [JsonElement].
     * @return This builder for fluent chaining.
     * @throws IllegalArgumentException if [value] is an unsupported type.
     */
    fun sdClaim(value: Any): SdJwtArrayBuilder {
        val index = arrayElements.size
        arrayElements.add(toJsonElementSafe(value))
        fieldsToConceal.add(currentPath.arrayElement(index))
        return this
    }

    /**
     * Appends a cleartext nested JSON object as an array element.
     *
     * The object element is visible in the payload, but its internal properties
     * may be individually concealed using the nested [builder] scope.
     *
     * @param minimumDigests The minimum number of digests (real + decoy) to enforce in
     *                       the nested object's `_sd` array. Defaults to `0`.
     * @param builder The nested [SdJwtObjectBuilder] block for defining child claims.
     * @return This builder for fluent chaining.
     */
    fun objClaim(minimumDigests: Int = 0, builder: SdJwtObjectBuilder.() -> Unit): SdJwtArrayBuilder {
        val index = arrayElements.size
        val childMap = mutableMapOf<String, JsonElement>()
        val childPath = currentPath.arrayElement(index)
        val childBuilder = SdJwtObjectBuilder(childPath, childMap, fieldsToConceal, decoyConstraints)
        childBuilder.builder()
        arrayElements.add(JsonObject(childMap))
        if (minimumDigests > 0) decoyConstraints[childPath] = minimumDigests
        return this
    }

    /**
     * Appends a selectively disclosable nested JSON object as an array element.
     *
     * The entire object element is concealed as a single array disclosure. Its internal
     * properties may also be individually concealed via the nested [builder] scope.
     *
     * @param minimumDigests The minimum number of digests (real + decoy) to enforce in
     *                       the nested object's `_sd` array. Defaults to `0`.
     * @param builder The nested [SdJwtObjectBuilder] block for defining child claims.
     * @return This builder for fluent chaining.
     */
    fun sdObjClaim(minimumDigests: Int = 0, builder: SdJwtObjectBuilder.() -> Unit): SdJwtArrayBuilder {
        val index = arrayElements.size
        val childMap = mutableMapOf<String, JsonElement>()
        val childPath = currentPath.arrayElement(index)
        val childBuilder = SdJwtObjectBuilder(childPath, childMap, fieldsToConceal, decoyConstraints)
        childBuilder.builder()
        arrayElements.add(JsonObject(childMap))
        fieldsToConceal.add(childPath)
        if (minimumDigests > 0) decoyConstraints[childPath] = minimumDigests
        return this
    }
}
