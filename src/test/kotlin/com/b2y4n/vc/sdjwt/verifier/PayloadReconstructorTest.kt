package com.b2y4n.vc.sdjwt.verifier

import com.b2y4n.vc.sdjwt.crypto.Sha256Hasher
import com.b2y4n.vc.sdjwt.models.Disclosure
import com.b2y4n.vc.sdjwt.models.SdJwtConstants
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PayloadReconstructorTest {

    private val hasher = Sha256Hasher()

    private fun hashDisclosure(encoded: String): String = hasher.hashBase64Url(encoded)

    @Test
    fun `reconstruct replaces _sd hashes with disclosure values`() {
        val disclosure = Disclosure("enc1", "salt", "email", JsonPrimitive("test@test.com"))
        val hash = hashDisclosure("enc1")
        val disclosureMap = mapOf(hash to disclosure)

        val payload = buildJsonObject {
            put("iss", "example.com")
            put(SdJwtConstants.CLAIM_SD, buildJsonArray { add(hash) })
        }

        val reconstructor = PayloadReconstructor(disclosureMap)
        val result = reconstructor.reconstruct(payload) as JsonObject

        assertEquals("test@test.com", result["email"]?.jsonPrimitive?.content)
        assertEquals("example.com", result["iss"]?.jsonPrimitive?.content)
        assertTrue(SdJwtConstants.CLAIM_SD !in result)
    }

    @Test
    fun `reconstruct strips _sd_alg from output`() {
        val payload = buildJsonObject {
            put("iss", "example.com")
            put(SdJwtConstants.CLAIM_SD_ALG, "sha-256")
        }

        val reconstructor = PayloadReconstructor(emptyMap())
        val result = reconstructor.reconstruct(payload) as JsonObject

        assertTrue(SdJwtConstants.CLAIM_SD_ALG !in result)
    }

    @Test
    fun `reconstruct skips decoy hashes without matching disclosure`() {
        val payload = buildJsonObject {
            put(SdJwtConstants.CLAIM_SD, buildJsonArray { add("nonexistent_hash") })
        }

        val reconstructor = PayloadReconstructor(emptyMap())
        val result = reconstructor.reconstruct(payload) as JsonObject

        assertTrue(SdJwtConstants.CLAIM_SD !in result)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `reconstruct throws on claim name collision`() {
        val disclosure = Disclosure("enc1", "salt", "iss", JsonPrimitive("attacker.com"))
        val hash = hashDisclosure("enc1")
        val disclosureMap = mapOf(hash to disclosure)

        val payload = buildJsonObject {
            put("iss", "example.com") // Already present
            put(SdJwtConstants.CLAIM_SD, buildJsonArray { add(hash) }) // Tries to add "iss" again
        }

        val reconstructor = PayloadReconstructor(disclosureMap)
        assertFailsWith<IllegalArgumentException> {
            reconstructor.reconstruct(payload)
        }
    }

    @Test
    fun `reconstruct throws when array element disclosure appears in object _sd array`() {
        // Array element disclosure has null claimName
        val disclosure = Disclosure("enc1", "salt", null, JsonPrimitive("value"))
        val hash = hashDisclosure("enc1")
        val disclosureMap = mapOf(hash to disclosure)

        val payload = buildJsonObject {
            put(SdJwtConstants.CLAIM_SD, buildJsonArray { add(hash) })
        }

        val reconstructor = PayloadReconstructor(disclosureMap)
        assertFailsWith<IllegalArgumentException> {
            reconstructor.reconstruct(payload)
        }
    }

    @Test
    fun `reconstruct throws when object property disclosure appears in array context`() {
        // Object property disclosure has non-null claimName
        val disclosure = Disclosure("enc1", "salt", "name", JsonPrimitive("John"))
        val hash = hashDisclosure("enc1")
        val disclosureMap = mapOf(hash to disclosure)

        val payload = buildJsonArray {
            add(buildJsonObject { put(SdJwtConstants.ARRAY_DECOY_KEY, hash) })
        }

        val reconstructor = PayloadReconstructor(disclosureMap)
        assertFailsWith<IllegalArgumentException> {
            reconstructor.reconstruct(payload)
        }
    }

    @Test
    fun `reconstruct replaces array dot-dot-dot wrappers with disclosure values`() {
        val disclosure = Disclosure("enc1", "salt", null, JsonPrimitive("swimming"))
        val hash = hashDisclosure("enc1")
        val disclosureMap = mapOf(hash to disclosure)

        val payload = buildJsonArray {
            add(JsonPrimitive("reading"))
            add(buildJsonObject { put(SdJwtConstants.ARRAY_DECOY_KEY, hash) })
        }

        val reconstructor = PayloadReconstructor(disclosureMap)
        val result = reconstructor.reconstruct(payload) as JsonArray

        assertEquals(2, result.size)
        assertEquals("reading", result[0].jsonPrimitive.content)
        assertEquals("swimming", result[1].jsonPrimitive.content)
    }

    @Test
    fun `reconstruct omits array decoy wrappers without matching disclosure`() {
        val payload = buildJsonArray {
            add(JsonPrimitive("reading"))
            add(buildJsonObject { put(SdJwtConstants.ARRAY_DECOY_KEY, "nonexistent_hash") })
        }

        val reconstructor = PayloadReconstructor(emptyMap())
        val result = reconstructor.reconstruct(payload) as JsonArray

        assertEquals(1, result.size)
        assertEquals("reading", result[0].jsonPrimitive.content)
    }

    @Test
    fun `reconstruct tracks used hashes correctly`() {
        val d1 = Disclosure("enc1", "s1", "name", JsonPrimitive("John"))
        val d2 = Disclosure("enc2", "s2", null, JsonPrimitive("swimming"))
        val hash1 = hashDisclosure("enc1")
        val hash2 = hashDisclosure("enc2")
        val disclosureMap = mapOf(hash1 to d1, hash2 to d2)

        val payload = buildJsonObject {
            put(SdJwtConstants.CLAIM_SD, buildJsonArray { add(hash1) })
            put("hobbies", buildJsonArray {
                add(buildJsonObject { put(SdJwtConstants.ARRAY_DECOY_KEY, hash2) })
            })
        }

        val reconstructor = PayloadReconstructor(disclosureMap)
        reconstructor.reconstruct(payload)

        assertEquals(setOf(hash1, hash2), reconstructor.usedHashes)
    }

    @Test
    fun `reconstruct returns primitive elements unchanged`() {
        val reconstructor = PayloadReconstructor(emptyMap())
        val primitive = JsonPrimitive("hello")

        val result = reconstructor.reconstruct(primitive)
        assertEquals(primitive, result)
    }

    @Test
    fun `reconstruct handles recursive nested objects`() {
        val innerDisclosure = Disclosure("encInner", "s1", "city", JsonPrimitive("Berlin"))
        val innerHash = hashDisclosure("encInner")

        val outerValue = buildJsonObject {
            put(SdJwtConstants.CLAIM_SD, buildJsonArray { add(innerHash) })
        }
        val outerDisclosure = Disclosure("encOuter", "s2", "address", outerValue)
        val outerHash = hashDisclosure("encOuter")

        val disclosureMap = mapOf(innerHash to innerDisclosure, outerHash to outerDisclosure)

        val payload = buildJsonObject {
            put(SdJwtConstants.CLAIM_SD, buildJsonArray { add(outerHash) })
        }

        val reconstructor = PayloadReconstructor(disclosureMap)
        val result = reconstructor.reconstruct(payload) as JsonObject

        val address = result["address"]?.jsonObject
        assertEquals("Berlin", address?.get("city")?.jsonPrimitive?.content)
    }
}
