package com.b2y4n.vc.sdjwt.models

import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DisclosureTest {

    @Test
    fun `equals returns true for same encoded value regardless of other fields`() {
        val d1 = Disclosure("encoded123", "salt1", "name", JsonPrimitive("John"))
        val d2 = Disclosure("encoded123", "differentSalt", "differentName", JsonPrimitive("Jane"))

        assertEquals(d1, d2, "Disclosures with same encoded value must be equal")
    }

    @Test
    fun `equals returns false for different encoded values`() {
        val d1 = Disclosure("encodedA", "salt1", "name", JsonPrimitive("John"))
        val d2 = Disclosure("encodedB", "salt1", "name", JsonPrimitive("John"))

        assertNotEquals(d1, d2)
    }

    @Test
    fun `equals returns true for referential equality`() {
        val d = Disclosure("enc", "salt", "name", JsonPrimitive("value"))
        assertTrue(d.equals(d))
    }

    @Test
    fun `equals returns false for non-Disclosure type`() {
        val d = Disclosure("enc", "salt", "name", JsonPrimitive("value"))
        assertFalse(d.equals("not a disclosure"))
    }

    @Test
    fun `equals returns false for null`() {
        val d = Disclosure("enc", "salt", "name", JsonPrimitive("value"))
        assertFalse(d.equals(null))
    }

    @Test
    fun `hashCode is consistent with equals for same encoded`() {
        val d1 = Disclosure("sameEncoded", "salt1", "name1", JsonPrimitive("v1"))
        val d2 = Disclosure("sameEncoded", "salt2", "name2", JsonPrimitive("v2"))

        assertEquals(d1.hashCode(), d2.hashCode(), "Equal disclosures must have same hashCode")
    }

    @Test
    fun `hashCode differs for different encoded values`() {
        val d1 = Disclosure("encodedX", "salt", "name", JsonPrimitive("v"))
        val d2 = Disclosure("encodedY", "salt", "name", JsonPrimitive("v"))

        // Not strictly required by contract, but practically expected
        assertNotEquals(d1.hashCode(), d2.hashCode())
    }

    @Test
    fun `Set deduplication works based on encoded field`() {
        val d1 = Disclosure("same", "s1", "n1", JsonPrimitive("v1"))
        val d2 = Disclosure("same", "s2", "n2", JsonPrimitive("v2"))
        val d3 = Disclosure("different", "s3", "n3", JsonPrimitive("v3"))

        val set = setOf(d1, d2, d3)
        assertEquals(2, set.size, "Set should deduplicate by encoded value")
    }

    @Test
    fun `copy preserves custom equality semantics`() {
        val original = Disclosure("enc", "salt", "name", JsonPrimitive("v"), path = null)
        val copied = original.copy(path = ClaimPath.claim("name"))

        assertEquals(original, copied, "copy() with different path should still be equal by encoded")
    }

    @Test
    fun `array element disclosure has null claimName`() {
        val d = Disclosure("enc", "salt", null, JsonPrimitive("value"))
        assertEquals(null, d.claimName)
    }
}
