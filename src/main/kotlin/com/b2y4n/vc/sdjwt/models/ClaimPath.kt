package com.b2y4n.vc.sdjwt.models

/**
 * A type-safe sealed class hierarchy representing a structural path to a specific claim
 * within a JSON payload tree.
 *
 * Replaces error-prone string-based path concatenation with a composable, immutable
 * abstraction. Each variant captures a distinct structural coordinate:
 *
 * - [Root]: The root of the JSON document (empty path).
 * - [Claim]: A named property within a JSON object (e.g., `address.city`).
 * - [ArrayElement]: An indexed element within a JSON array (e.g., `scores[0]`).
 *
 * Paths are constructed by chaining [claim] and [arrayElement] calls from the [root]
 * starting point:
 * ```kotlin
 * val path = ClaimPath.root.claim("address").claim("city")
 * // asString == "address.city"
 * ```
 *
 * @see com.b2y4n.vc.sdjwt.issuer.PayloadConcealer
 * @see com.b2y4n.vc.sdjwt.presenter.SdJwtPresenter
 */
sealed class ClaimPath {
    /**
     * The dot-delimited string representation of this path.
     *
     * - [Root] yields an empty string `""`.
     * - [Claim] yields `"parent.name"` (or just `"name"` if parent is [Root]).
     * - [ArrayElement] yields `"parent[index]"`.
     */
    abstract val asString: String

    /**
     * Represents the root of the JSON document, serving as the origin for all path traversal.
     *
     * The root path has an empty string representation and acts as the implicit parent
     * of all top-level claims.
     */
    data object Root : ClaimPath() {
        override val asString = ""
    }

    /**
     * Represents a named property within a JSON object.
     *
     * @property parent The parent [ClaimPath] from which this claim descends.
     * @property name The JSON object key for this claim.
     */
    data class Claim(val parent: ClaimPath, val name: String) : ClaimPath() {
        override val asString: String
            get() = if (parent is Root) name else "${parent.asString}.$name"
    }

    /**
     * Represents an indexed element within a JSON array.
     *
     * @property parent The parent [ClaimPath] from which this array element descends.
     * @property index The zero-based index of the element within the array.
     */
    data class ArrayElement(val parent: ClaimPath, val index: Int) : ClaimPath() {
        override val asString: String
            get() = "${parent.asString}[$index]"
    }

    /**
     * Creates a child [Claim] path by appending a named property to this path.
     *
     * @param name The JSON object key for the child claim.
     * @return A new [Claim] path with this path as its parent.
     */
    fun claim(name: String): ClaimPath = Claim(this, name)

    /**
     * Creates a child [ArrayElement] path by appending an array index to this path.
     *
     * @param index The zero-based index of the element within the JSON array.
     * @return A new [ArrayElement] path with this path as its parent.
     */
    fun arrayElement(index: Int): ClaimPath = ArrayElement(this, index)

    /**
     * Determines whether this path is a sub-path (descendant or equal) of [other].
     *
     * Traverses the parent chain from this path upward, returning `true` if [other]
     * is encountered at any level. This is used during selective disclosure to determine
     * whether a claim falls within a user-selected disclosure boundary.
     *
     * @param other The potential ancestor or equal [ClaimPath] to compare against.
     * @return `true` if this path is the same as or a descendant of [other]; `false` otherwise.
     */
    fun isSubPathOf(other: ClaimPath): Boolean {
        var current: ClaimPath? = this
        while (current != null) {
            if (current == other) return true
            current = when (current) {
                is Claim -> current.parent
                is ArrayElement -> current.parent
                is Root -> null
            }
        }
        return false
    }

    /**
     * Returns the dot-delimited string representation of this path.
     *
     * @return The value of [asString].
     */
    override fun toString(): String = asString

    companion object {
        /**
         * Creates a top-level [Claim] path directly under the document root.
         *
         * @param name The JSON object key for the top-level claim.
         * @return A [Claim] path with [Root] as its parent.
         */
        fun claim(name: String): ClaimPath = Claim(Root, name)
        
        /**
         * The singleton root path representing the top of the JSON document.
         */
        val root: ClaimPath = Root
    }
}
