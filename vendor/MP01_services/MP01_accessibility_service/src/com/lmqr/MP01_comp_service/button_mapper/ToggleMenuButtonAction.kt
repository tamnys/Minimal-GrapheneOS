package com.lmqr.hMP01_comp_service.button_mapper

import android.content.Context
import com.lmqr.hMP01_comp_service.MP01AccessibilityService

class ToggleMenuButtonAction : ButtonAction {
    override fun execute(context: Context) {
        (context as? MP01AccessibilityService)?.openFloatingMenu()
    }
}