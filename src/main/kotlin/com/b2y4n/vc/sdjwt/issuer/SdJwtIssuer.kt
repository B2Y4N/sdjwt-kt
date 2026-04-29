package com.b2y4n.vc.sdjwt.issuer

import com.b2y4n.vc.sdjwt.crypto.Hasher
import com.b2y4n.vc.sdjwt.crypto.Sha256Hasher
import com.b2y4n.vc.sdjwt.models.ClaimPath
import com.b2y4n.vc.sdjwt.models.Disclosure
import com.b2y4n.vc.sdjwt.models.SdJwtConstants
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.SecureRandom

/**
 * Orchestrates the issuance of Selective Disclosure JWTs (SD-JWT) as defined in
 * [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html).
 *
 * This class is the primary entry point for creating SD-JWTs. It is designed to be
 * **stateless** and mathematically pure: it delegates payload concealment to
 * [PayloadConcealer] and cryptographic signing to the injected [JwtSigner].
 *
 * The issuance flow:
 * 1. Recursively conceals the payload claims specified in [SdJwtClaims.fieldsToConceal].
 * 2. Appends the `_sd_alg` claim to identify the hash algorithm used for disclosure digests.
 * 3. Constructs a default JWS header (if none provided) with `alg` and `typ: sd-jwt`.
 * 4. Signs the final payload and serializes the result as `<jwt>~<disclosure_1>~...~<disclosure_n>~`.
 *
 * @property signer The [JwtSigner] responsible for signing the final JWT payload.
 * @property saltGenerator The [SaltGenerator] used to produce random salts for each disclosure.
 * @property hasher The [Hasher] used to compute disclosure digests. Defaults to [Sha256Hasher].
 * @property secureRandom The [SecureRandom] source for decoy padding. Defaults to a new instance.
 * @constructor Creates an [SdJwtIssuer] with the specified signing and hashing dependencies.
 */
class SdJwtIssuer(
    private val signer: JwtSigner,
    private val saltGenerator: SaltGenerator,
    private val hasher: Hasher = Sha256Hasher(),
    private val secureRandom: SecureRandom = SecureRandom()
) {
    private val payloadConcealer = PayloadConcealer(saltGenerator, hasher, secureRandom)

    /**
     * Issues an SD-JWT by concealing the specified claims and signing the resulting payload.
     *
     * The method processes the [SdJwtClaims] configuration to produce a complete SD-JWT
     * string containing the signed base JWT and all generated disclosure strings.
     *
     * @param claims The [SdJwtClaims] configuration specifying the payload, claims to conceal,
     *               and decoy constraints.
     * @param header An optional custom [JsonObject] for the JWS header. If `null`, a default
     *               header is constructed with `alg` from [JwtSigner.algorithm] and
     *               `typ` set to `"sd-jwt"`.
     * @return The serialized SD-JWT string in the format
     *         `<jwt>~<disclosure_1>~...~<disclosure_n>~`. If no disclosures were generated,
     *         returns `<jwt>~`.
     */
    fun issue(claims: SdJwtClaims, header: JsonObject? = null): String {
        val payload = claims.payload
        val disclosures = mutableListOf<Disclosure>()

        val modifiedPayload = payloadConcealer.conceal(payload, ClaimPath.root, claims.fieldsToConceal, claims.decoyConstraints, disclosures) as JsonObject

        val finalPayloadMap = modifiedPayload.toMutableMap()
        if (disclosures.isNotEmpty()) {
            finalPayloadMap[SdJwtConstants.CLAIM_SD_ALG] = JsonPrimitive(hasher.algorithmName)
        }
        
        val finalHeader = header ?: buildJsonObject {
            put("alg", signer.algorithm)
            put("typ", SdJwtConstants.HEADER_TYP_SD_JWT)
        }
        
        val baseJwt = signer.sign(finalHeader, JsonObject(finalPayloadMap))

        val encodedDisclosures = disclosures.joinToString("~") { it.encoded }
        
        return if (encodedDisclosures.isNotEmpty()) {
            "$baseJwt~$encodedDisclosures~"
        } else {
            "$baseJwt~"
        }
    }
}
