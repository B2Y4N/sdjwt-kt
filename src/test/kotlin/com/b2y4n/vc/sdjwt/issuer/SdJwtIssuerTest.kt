package com.b2y4n.vc.sdjwt.issuer

import com.b2y4n.vc.sdjwt.models.SdJwtConstants
import kotlinx.serialization.json.*
import java.util.*
import kotlin.test.*

class SdJwtIssuerTest {

    private val dummySigner = object : JwtSigner {
        override val algorithm = "ES256"
        
        override fun sign(header: JsonObject, payload: JsonObject): String {
            val h = Base64.getUrlEncoder().withoutPadding().encodeToString(header.toString().toByteArray())
            val p = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toString().toByteArray())
            return "$h.$p.signature"
        }
    }

    private val staticSaltGenerator = object : SaltGenerator {
        override fun generateSalt() = "salt123"
    }

    @Test
    fun `issue conceals top level claims and adds _sd array`() {
        val claimsHolder = SdJwtClaims(minimumDigests = 3) {
            claim("iss", "https://example.com")
            sdClaim("name", "John")
            sdClaim("email", "john@example.com")
            claim("age", 30)
        }
            
        val issuer = SdJwtIssuer(dummySigner, staticSaltGenerator)

        val sdJwtString = issuer.issue(claimsHolder)
        
        val parts = sdJwtString.split("~")
        // baseJwt + name + email + kbJwt -> 4 parts. The fake extra decoy isn't a string disclosure appended!
        assertEquals(4, parts.size) 
        
        val headerPartStr = String(Base64.getUrlDecoder().decode(parts[0].split(".")[0]))
        val decodedHeader = Json.parseToJsonElement(headerPartStr).jsonObject
        assertEquals("ES256", decodedHeader["alg"]?.jsonPrimitive?.content)
        assertEquals(SdJwtConstants.HEADER_TYP_SD_JWT, decodedHeader["typ"]?.jsonPrimitive?.content)
        
        val decodedPayload = Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(parts[0].split(".")[1]))).jsonObject

        assertTrue("name" !in decodedPayload)
        
        val sdArray = decodedPayload[SdJwtConstants.CLAIM_SD]?.jsonArray
        assertNotNull(sdArray)
        // 2 real disclosures + minimumDigests constraint = 3 items!
        assertEquals(3, sdArray.size)
    }

    @Test
    fun `issue does nothing when no fields are concealed`() {
        val claimsHolder = SdJwtClaims {
            claim("iss", "https://example.com")
            claim("name", "John")
        }
            
        val issuer = SdJwtIssuer(dummySigner, staticSaltGenerator)

        // Passing explicitly null defaults to automatic ES256 header correctly handled.
        val sdJwtString = issuer.issue(claimsHolder, header = null)
        
        val parts = sdJwtString.split("~")
        assertEquals(2, parts.size)
        val decodedPayload = Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(parts[0].split(".")[1]))).jsonObject

        assertTrue("name" in decodedPayload)
        assertTrue(SdJwtConstants.CLAIM_SD !in decodedPayload)
    }

    @Test
    fun `issue conceals nested object property and adds _sd array inline`() {
        val claimsHolder = SdJwtClaims {
            claim("name", "John")
            objClaim("address", minimumDigests = 2) {
                sdClaim("city", "NYC")
                claim("state", "NY")
            }
        }

        val issuer = SdJwtIssuer(dummySigner, staticSaltGenerator)
        val sdJwtString = issuer.issue(claimsHolder)
        val decodedPayload = Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(sdJwtString.split("~")[0].split(".")[1]))).jsonObject

        val addressObj = decodedPayload["address"]?.jsonObject
        assertNotNull(addressObj)
        assertTrue("city" !in addressObj)
        assertEquals("NY", addressObj["state"]?.jsonPrimitive?.content)

        val addressSdArray = addressObj[SdJwtConstants.CLAIM_SD]?.jsonArray
        assertNotNull(addressSdArray)
        // Minimum digests = 2. Real = 1 ("city"). Decoy = 1.
        assertEquals(2, addressSdArray.size)
    }

    @Test
    fun `issue conceals array element and adds dot-dot-dot replacement`() {
        val claimsHolder = SdJwtClaims {
            arrClaim("hobbies", minimumDigests = 4) {
                claim("reading")
                sdClaim("swimming")
            }
        }

        val issuer = SdJwtIssuer(dummySigner, staticSaltGenerator)
        val sdJwtString = issuer.issue(claimsHolder)
        val parts = sdJwtString.split("~")
        
        val decodedPayload = Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(parts[0].split(".")[1]))).jsonObject
        val hobbiesArray = decodedPayload["hobbies"]?.jsonArray
        assertNotNull(hobbiesArray)
        // 1 normal + max(4, 1 real hidden) -> 1 normal + 4 hidden objects = 5 loop length.
        assertEquals(5, hobbiesArray.size)
        
        // Unchanged
        assertTrue(hobbiesArray.any { it is JsonPrimitive && it.content == "reading" })
        
        // 4 elements should be `{ SdJwtConstants.ARRAY_DECOY_KEY: "<hash>" }` objects
        val dotObjects = hobbiesArray.filter { it is JsonObject && it.containsKey(SdJwtConstants.ARRAY_DECOY_KEY) }
        assertEquals(4, dotObjects.size)
    }

    @Test
    fun `issue correctly handles recursive concealment`() {
        val claimsHolder = SdJwtClaims {
            sdObjClaim("address", minimumDigests = 1) {
                sdClaim("city", "NYC")
                claim("state", "NY")
            }
        }

        val issuer = SdJwtIssuer(dummySigner, staticSaltGenerator)
        val sdJwtString = issuer.issue(claimsHolder)
        val parts = sdJwtString.split("~")

        val decodedPayload = Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(parts[0].split(".")[1]))).jsonObject
        assertTrue("address" !in decodedPayload)
        
        val baseSdArray = decodedPayload[SdJwtConstants.CLAIM_SD]?.jsonArray
        assertNotNull(baseSdArray)
        assertEquals(1, baseSdArray.size)
    }

    @Test
    fun `security critical root claims cannot be selectively disclosable`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            SdJwtClaims {
                sdClaim("iss", "https://example.com")
            }
        }
        assertTrue(exception.message!!.contains("Security critical claim"))
    }

    @Test
    fun `security critical root claims cannot be concealed via sdObjClaim`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            SdJwtClaims {
                sdObjClaim("cnf") {
                    claim("jwk", "{}")
                }
            }
        }
        assertTrue(exception.message!!.contains("Security critical claim"))
    }

    @Test
    fun `security critical root claims cannot be concealed via sdArrClaim`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            SdJwtClaims {
                sdArrClaim("cnf") {
                    claim("value")
                }
            }
        }
        assertTrue(exception.message!!.contains("Security critical claim"))
    }

    @Test
    fun `issue with sdArrClaim conceals entire array as single disclosure`() {
        val claimsHolder = SdJwtClaims {
            sdArrClaim("hobbies") {
                claim("reading")
                sdClaim("swimming")
            }
        }

        val issuer = SdJwtIssuer(dummySigner, staticSaltGenerator)
        val sdJwtString = issuer.issue(claimsHolder)
        val decodedPayload = Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(sdJwtString.split("~")[0].split(".")[1]))).jsonObject

        // The entire "hobbies" array should be concealed (not present in payload)
        assertTrue("hobbies" !in decodedPayload)
        val sdArray = decodedPayload[SdJwtConstants.CLAIM_SD]?.jsonArray
        assertNotNull(sdArray)
        assertTrue(sdArray.isNotEmpty())
    }

    @Test
    fun `issue with addObjClaim adds cleartext nested object inside array`() {
        val claimsHolder = SdJwtClaims {
            arrClaim("people") {
                objClaim {
                    claim("name", "Alice")
                    sdClaim("age", 30)
                }
            }
        }

        val issuer = SdJwtIssuer(dummySigner, staticSaltGenerator)
        val sdJwtString = issuer.issue(claimsHolder)
        val decodedPayload = Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(sdJwtString.split("~")[0].split(".")[1]))).jsonObject

        val people = decodedPayload["people"]?.jsonArray
        assertNotNull(people)
        assertEquals(1, people.size)
        val personObj = people[0].jsonObject
        assertEquals("Alice", personObj["name"]?.jsonPrimitive?.content)
        // "age" should be concealed
        assertTrue("age" !in personObj)
        val innerSd = personObj[SdJwtConstants.CLAIM_SD]?.jsonArray
        assertNotNull(innerSd)
    }

    @Test
    fun `issue with addSdObjClaim conceals nested object as array element disclosure`() {
        val claimsHolder = SdJwtClaims {
            arrClaim("people") {
                sdObjClaim {
                    claim("name", "Bob")
                }
                claim("plainValue")
            }
        }

        val issuer = SdJwtIssuer(dummySigner, staticSaltGenerator)
        val sdJwtString = issuer.issue(claimsHolder)
        val decodedPayload = Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(sdJwtString.split("~")[0].split(".")[1]))).jsonObject

        val people = decodedPayload["people"]?.jsonArray
        assertNotNull(people)
        // Should have 2 elements: one concealed ({"...": hash}), one plain
        assertEquals(2, people.size)
        val concealedElements = people.filter { it is JsonObject && it.jsonObject.containsKey(SdJwtConstants.ARRAY_DECOY_KEY) }
        assertEquals(1, concealedElements.size)
    }

    @Test
    fun `issue with custom header uses provided header instead of default`() {
        val customHeader = buildJsonObject {
            put("alg", "RS256")
            put("typ", "custom-type")
            put("kid", "key-123")
        }
        val claimsHolder = SdJwtClaims {
            claim("iss", "https://example.com")
        }

        val issuer = SdJwtIssuer(dummySigner, staticSaltGenerator)
        val sdJwtString = issuer.issue(claimsHolder, header = customHeader)

        val headerPartStr = String(Base64.getUrlDecoder().decode(sdJwtString.split("~")[0].split(".")[0]))
        val decodedHeader = Json.parseToJsonElement(headerPartStr).jsonObject

        assertEquals("RS256", decodedHeader["alg"]?.jsonPrimitive?.content)
        assertEquals("custom-type", decodedHeader["typ"]?.jsonPrimitive?.content)
        assertEquals("key-123", decodedHeader["kid"]?.jsonPrimitive?.content)
    }

    @Test
    fun `toJsonElementSafe throws for unsupported type`() {
        assertFailsWith<IllegalArgumentException> {
            toJsonElementSafe(listOf("unsupported"))
        }
    }

    @Test
    fun `toJsonElementSafe passes through JsonElement directly`() {
        val element = JsonPrimitive("already json")
        val result = toJsonElementSafe(element)
        assertEquals(element, result)
    }
}
