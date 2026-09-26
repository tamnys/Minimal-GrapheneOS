package com.lmqr.hMP01_comp_service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MP01FrameworkSettingsTest {
    @Test
    fun resolvesKnownThemeAndFallsBackToSpritz() {
        assertEquals("TONAL_SPOT", MP01FrameworkSettings.resolveThemeStyle("0"))
        assertEquals("SPRITZ", MP01FrameworkSettings.resolveThemeStyle("5"))
        assertEquals("SPRITZ", MP01FrameworkSettings.resolveThemeStyle("99"))
        assertEquals("SPRITZ", MP01FrameworkSettings.resolveThemeStyle("invalid"))
        assertEquals("SPRITZ", MP01FrameworkSettings.resolveThemeStyle(null))
    }

    @Test
    fun acceptsOnlyFourDigitNonNegativeBrightness() {
        assertEquals(0, MP01FrameworkSettings.parseMaxBrightness("0"))
        assertEquals(2200, MP01FrameworkSettings.parseMaxBrightness("2200"))
        assertEquals(9999, MP01FrameworkSettings.parseMaxBrightness("9999"))
        assertNull(MP01FrameworkSettings.parseMaxBrightness("-1"))
        assertNull(MP01FrameworkSettings.parseMaxBrightness("10000"))
        assertNull(MP01FrameworkSettings.parseMaxBrightness("invalid"))
        assertNull(MP01FrameworkSettings.parseMaxBrightness(null))
    }
}
