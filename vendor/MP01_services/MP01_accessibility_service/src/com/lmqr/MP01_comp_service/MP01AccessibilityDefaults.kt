package com.lmqr.hMP01_comp_service

internal interface AccessibilityDefaultSettings {
    fun isInitialized(): Boolean
    fun isSetupComplete(): Boolean
    fun isServiceEnabled(): Boolean
    fun addService(): Boolean
    fun enableAccessibility(): Boolean
    fun markInitialized(): Boolean
}

internal object MP01AccessibilityDefaults {
    fun apply(settings: AccessibilityDefaultSettings): Boolean {
        if (settings.isInitialized()) return true

        // A completed setup with no marker may be an upgrade. Never infer that
        // an absent service should be restored after the user could disable it.
        if (settings.isSetupComplete()) return settings.markInitialized()

        if (!settings.isServiceEnabled() && !settings.addService()) return false
        if (!settings.enableAccessibility()) return false
        return settings.markInitialized()
    }
}
