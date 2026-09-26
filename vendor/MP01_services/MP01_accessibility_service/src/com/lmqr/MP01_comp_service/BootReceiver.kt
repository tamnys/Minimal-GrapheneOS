package com.lmqr.hMP01_comp_service

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.util.Log

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }

        MP01Defaults.applyIfNeeded(context)
        val resolver = context.contentResolver
        val serviceComponent = ComponentName(context, MP01AccessibilityService::class.java)
        val settings = object : AccessibilityDefaultSettings {
            override fun isInitialized() = Settings.Secure.getInt(
                resolver, "mp01_accessibility_default_applied", 0) == 1

            override fun isSetupComplete() = Settings.Secure.getInt(
                resolver, "user_setup_complete", 0) == 1

            override fun isServiceEnabled(): Boolean = Settings.Secure.getString(
                resolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).orEmpty()
                .split(':')
                .any { ComponentName.unflattenFromString(it) == serviceComponent }

            override fun addService(): Boolean {
                val enabledServices = Settings.Secure.getString(
                    resolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).orEmpty()
                val updatedServices = (enabledServices.split(':').filter { it.isNotEmpty() } +
                    serviceComponent.flattenToString()).joinToString(":")
                return Settings.Secure.putString(
                    resolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, updatedServices)
            }

            override fun enableAccessibility() = Settings.Secure.putInt(
                resolver, Settings.Secure.ACCESSIBILITY_ENABLED, 1)

            override fun markInitialized() = Settings.Secure.putInt(
                resolver, "mp01_accessibility_default_applied", 1)
        }

        try {
            if (!MP01AccessibilityDefaults.apply(settings)) {
                Log.e("MP01BootReceiver", "Failed to initialize accessibility default")
            }
        } catch (e: Exception) {
            Log.e("MP01BootReceiver", "Failed to initialize accessibility default", e)
        }
    }
}
