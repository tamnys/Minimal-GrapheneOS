package com.lmqr.hMP01_comp_service.button_mapper

import SystemSettingsManager
import android.content.Context

class ToggleNightLightAction : ButtonAction {
    override fun execute(context: Context) {
        SystemSettingsManager.toggleNightLightMode(context)
    }
}