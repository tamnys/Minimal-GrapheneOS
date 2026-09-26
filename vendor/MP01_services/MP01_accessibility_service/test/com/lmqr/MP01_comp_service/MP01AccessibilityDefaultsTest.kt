package com.lmqr.hMP01_comp_service

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MP01AccessibilityDefaultsTest {
    private class Settings(
        var initialized: Boolean = false,
        var setupComplete: Boolean = false,
        var serviceEnabled: Boolean = false,
        var accessibilityEnabled: Boolean = false,
        var allowEnable: Boolean = true,
    ) : AccessibilityDefaultSettings {
        override fun isInitialized() = initialized
        override fun isSetupComplete() = setupComplete
        override fun isServiceEnabled() = serviceEnabled
        override fun addService(): Boolean {
            serviceEnabled = true
            return true
        }
        override fun enableAccessibility(): Boolean {
            if (!allowEnable) return false
            accessibilityEnabled = true
            return true
        }
        override fun markInitialized(): Boolean {
            initialized = true
            return true
        }
    }

    @Test
    fun firstSetupEnablesOnceAndLaterDisableSurvivesBoot() {
        val settings = Settings()
        assertTrue(MP01AccessibilityDefaults.apply(settings))
        assertTrue(settings.serviceEnabled)
        assertTrue(settings.accessibilityEnabled)
        assertTrue(settings.initialized)

        settings.setupComplete = true
        settings.serviceEnabled = false
        settings.accessibilityEnabled = false
        assertTrue(MP01AccessibilityDefaults.apply(settings))
        assertFalse(settings.serviceEnabled)
        assertFalse(settings.accessibilityEnabled)
    }

    @Test
    fun completedSetupWithNoMarkerPreservesExistingChoice() {
        val settings = Settings(setupComplete = true)
        assertTrue(MP01AccessibilityDefaults.apply(settings))
        assertTrue(settings.initialized)
        assertFalse(settings.serviceEnabled)
        assertFalse(settings.accessibilityEnabled)
    }

    @Test
    fun failedEnableDoesNotMarkInitialization() {
        val settings = Settings(allowEnable = false)
        assertFalse(MP01AccessibilityDefaults.apply(settings))
        assertFalse(settings.initialized)

        settings.allowEnable = true
        assertTrue(MP01AccessibilityDefaults.apply(settings))
        assertTrue(settings.accessibilityEnabled)
        assertTrue(settings.initialized)
    }
}
