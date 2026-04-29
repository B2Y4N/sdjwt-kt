package com.b2y4n.vc.sdjwt.models

import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class SdJwtPresentationTest {

    @Test
    fun `toString delegates to wrapped SdJwt toString`() {
        val d = Disclosure("disc1", "s", "name", JsonPrimitive("v"))
        val sdJwt = SdJwt(jwt = "h.p.s", disclosures = listOf(d), kbJwt = "kb.jwt.sig")
        val presentation = SdJwtPresentation(sdJwt)

        assertEquals(sdJwt.toString(), presentation.toString())
    }

    @Test
    fun `toString without disclosures delegates correctly`() {
        val sdJwt = SdJwt(jwt = "header.payload.sig")
        val presentation = SdJwtPresentation(sdJwt)

        assertEquals("header.payload.sig~", presentation.toString())
    }
}
