package com.b2y4n.vc.sdjwt.models

import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class SdJwtTest {

    @Test
    fun `toString with no disclosures and no kbJwt produces jwt tilde`() {
        val sdJwt = SdJwt(jwt = "header.payload.sig")
        assertEquals("header.payload.sig~", sdJwt.toString())
    }

    @Test
    fun `toString with disclosures and no kbJwt produces jwt tilde disclosures tilde`() {
        val d1 = Disclosure("disc1", "s1", "name", JsonPrimitive("v1"))
        val d2 = Disclosure("disc2", "s2", "email", JsonPrimitive("v2"))
        val sdJwt = SdJwt(jwt = "header.payload.sig", disclosures = listOf(d1, d2))

        assertEquals("header.payload.sig~disc1~disc2~", sdJwt.toString())
    }

    @Test
    fun `toString with no disclosures and kbJwt produces jwt tilde kbJwt`() {
        val sdJwt = SdJwt(jwt = "header.payload.sig", kbJwt = "kb.header.sig")
        assertEquals("header.payload.sig~kb.header.sig", sdJwt.toString())
    }

    @Test
    fun `toString with disclosures and kbJwt produces full format`() {
        val d = Disclosure("disc1", "s1", "name", JsonPrimitive("v"))
        val sdJwt = SdJwt(jwt = "header.payload.sig", disclosures = listOf(d), kbJwt = "kb.jwt.sig")

        assertEquals("header.payload.sig~disc1~kb.jwt.sig", sdJwt.toString())
    }

    @Test
    fun `toString with single disclosure produces correct delimiters`() {
        val d = Disclosure("onlyDisc", "s", "key", JsonPrimitive("val"))
        val sdJwt = SdJwt(jwt = "h.p.s", disclosures = listOf(d))

        assertEquals("h.p.s~onlyDisc~", sdJwt.toString())
    }
}
