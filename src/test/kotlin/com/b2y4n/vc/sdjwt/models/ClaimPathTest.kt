package com.b2y4n.vc.sdjwt.models

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ClaimPathTest {

    // --- asString ---

    @Test
    fun `Root asString returns empty string`() {
        assertEquals("", ClaimPath.Root.asString)
    }

    @Test
    fun `Claim directly under Root returns just the name`() {
        val path = ClaimPath.Root.claim("name")
        assertEquals("name", path.asString)
    }

    @Test
    fun `Nested Claim returns dot-delimited path`() {
        val path = ClaimPath.Root.claim("address").claim("city")
        assertEquals("address.city", path.asString)
    }

    @Test
    fun `Deeply nested Claim returns full dot-delimited path`() {
        val path = ClaimPath.Root.claim("a").claim("b").claim("c").claim("d")
        assertEquals("a.b.c.d", path.asString)
    }

    @Test
    fun `ArrayElement directly under Root returns bracket notation`() {
        val path = ClaimPath.Root.arrayElement(0)
        assertEquals("[0]", path.asString)
    }

    @Test
    fun `ArrayElement under Claim returns parent dot name with bracket`() {
        val path = ClaimPath.Root.claim("hobbies").arrayElement(2)
        assertEquals("hobbies[2]", path.asString)
    }

    @Test
    fun `Mixed nesting of Claims and ArrayElements`() {
        val path = ClaimPath.Root.claim("records").arrayElement(0).claim("address").claim("city")
        assertEquals("records[0].address.city", path.asString)
    }


    // --- Companion shortcuts ---

    @Test
    fun `Companion claim creates top-level Claim under Root`() {
        val path = ClaimPath.claim("email")
        assertEquals("email", path.asString)
        assertTrue(path is ClaimPath.Claim)
        assertEquals(ClaimPath.Root, path.parent)
    }

    @Test
    fun `Companion root returns Root singleton`() {
        assertEquals(ClaimPath.Root, ClaimPath.root)
        assertEquals("", ClaimPath.root.asString)
    }

    // --- Factory chaining ---

    @Test
    fun `claim factory returns Claim with correct parent`() {
        val parent = ClaimPath.Root.claim("parent")
        val child = parent.claim("child")
        assertTrue(child is ClaimPath.Claim)
        assertEquals(parent, child.parent)
    }

    @Test
    fun `arrayElement factory returns ArrayElement with correct parent and index`() {
        val parent = ClaimPath.Root.claim("items")
        val elem = parent.arrayElement(5)
        assertTrue(elem is ClaimPath.ArrayElement)
        assertEquals(parent, elem.parent)
        assertEquals(5, elem.index)
    }

    // --- isSubPathOf ---

    @Test
    fun `isSubPathOf returns true for same path`() {
        val path = ClaimPath.Root.claim("address").claim("city")
        assertTrue(path.isSubPathOf(path))
    }

    @Test
    fun `isSubPathOf returns true for direct parent`() {
        val parent = ClaimPath.Root.claim("address")
        val child = parent.claim("city")
        assertTrue(child.isSubPathOf(parent))
    }

    @Test
    fun `isSubPathOf returns true for Root ancestor`() {
        val path = ClaimPath.Root.claim("a").claim("b").claim("c")
        assertTrue(path.isSubPathOf(ClaimPath.Root))
    }

    @Test
    fun `isSubPathOf returns true for deeply nested descendant`() {
        val ancestor = ClaimPath.Root.claim("records")
        val descendant = ancestor.arrayElement(0).claim("address").claim("city")
        assertTrue(descendant.isSubPathOf(ancestor))
    }

    @Test
    fun `isSubPathOf returns false for unrelated paths`() {
        val path1 = ClaimPath.Root.claim("name")
        val path2 = ClaimPath.Root.claim("email")
        assertFalse(path1.isSubPathOf(path2))
    }

    @Test
    fun `isSubPathOf returns false for child checking against descendant`() {
        val parent = ClaimPath.Root.claim("address")
        val child = parent.claim("city")
        // parent is NOT a sub-path of child
        assertFalse(parent.isSubPathOf(child))
    }

    @Test
    fun `isSubPathOf returns true for Root checking against itself`() {
        assertTrue(ClaimPath.Root.isSubPathOf(ClaimPath.Root))
    }

    @Test
    fun `isSubPathOf works with ArrayElement paths`() {
        val arr = ClaimPath.Root.claim("items")
        val elem = arr.arrayElement(3)
        assertTrue(elem.isSubPathOf(arr))
        assertFalse(arr.isSubPathOf(elem))
    }

    @Test
    fun `isSubPathOf returns false for sibling array elements`() {
        val arr = ClaimPath.Root.claim("items")
        val elem0 = arr.arrayElement(0)
        val elem1 = arr.arrayElement(1)
        assertFalse(elem0.isSubPathOf(elem1))
        assertFalse(elem1.isSubPathOf(elem0))
    }

    // --- data class equality ---

    @Test
    fun `Claim data class equality based on parent and name`() {
        val a = ClaimPath.Claim(ClaimPath.Root, "name")
        val b = ClaimPath.Claim(ClaimPath.Root, "name")
        assertEquals(a, b)
    }

    @Test
    fun `ArrayElement data class equality based on parent and index`() {
        val parent = ClaimPath.Root.claim("items")
        val a = ClaimPath.ArrayElement(parent, 0)
        val b = ClaimPath.ArrayElement(parent, 0)
        assertEquals(a, b)
    }
}
