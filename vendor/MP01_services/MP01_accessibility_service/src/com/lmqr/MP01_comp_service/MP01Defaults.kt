package com.lmqr.hMP01_comp_service

import android.app.UiModeManager
import android.content.Context
import android.provider.Settings
import android.util.Log

object MP01Defaults {
    private const val TAG = "MP01Defaults"
    private const val DEFAULTS_VERSION = 1
    private const val KEY_DEFAULTS_VERSION = "mp01_defaults_version"
    private const val KEY_FORCE_DEFAULTS = "persist.mp01.defaults.force"
    private const val KEY_UI_NIGHT_MODE = "ui_night_mode"
    private const val KEY_USER_SETUP_COMPLETE = "user_setup_complete"

    fun applyIfNeeded(context: Context): Boolean {
        val resolver = context.contentResolver
        val forceDefaults = MP01SystemProperties.get(KEY_FORCE_DEFAULTS, "") == "1"
        val appliedVersion = Settings.Secure.getInt(resolver, KEY_DEFAULTS_VERSION, 0)
        val userSetupComplete = Settings.Secure.getInt(resolver, KEY_USER_SETUP_COMPLETE, 0) == 1

        if (!forceDefaults && appliedVersion >= DEFAULTS_VERSION) {
            Log.d(TAG, "MP01 defaults already applied at version $appliedVersion")
            return true
        }

        if (!forceDefaults && userSetupComplete) {
            Log.d(TAG, "Skipping MP01 defaults because user setup is complete")
            return false
        }

        return try {
            val wroteLightMode = Settings.Secure.putInt(
                resolver,
                KEY_UI_NIGHT_MODE,
                UiModeManager.MODE_NIGHT_NO)
            if (!wroteLightMode) {
                Log.e(TAG, "Failed to set MP01 light mode default")
                return false
            }

            val wroteVersion = Settings.Secure.putInt(
                resolver,
                KEY_DEFAULTS_VERSION,
                DEFAULTS_VERSION)
            if (!wroteVersion) {
                Log.e(TAG, "Failed to record MP01 defaults version")
                return false
            }

            Log.i(TAG, "Applied MP01 defaults version $DEFAULTS_VERSION")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to apply MP01 defaults", e)
            false
        }
    }
}
