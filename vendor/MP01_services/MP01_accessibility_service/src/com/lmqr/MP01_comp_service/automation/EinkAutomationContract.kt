package com.lmqr.hMP01_comp_service.automation

object EinkAutomationContract {
    const val PERMISSION_CONTROL_EINK_REFRESH =
        "com.lmqr.hMP01_comp_service.permission.CONTROL_EINK_REFRESH"

    const val ACTION_EINK_FORCE_CLEAR =
        "com.lmqr.hMP01_comp_service.action.EINK_FORCE_CLEAR"
    const val ACTION_EINK_SET_REFRESH_MODE =
        "com.lmqr.hMP01_comp_service.action.EINK_SET_REFRESH_MODE"

    const val EXTRA_REFRESH_MODE =
        "com.lmqr.hMP01_comp_service.extra.REFRESH_MODE"

    const val MODE_BALANCED = "balanced"
    const val MODE_SMOOTH = "smooth"
    const val MODE_SPEED = "speed"

    val PUBLIC_ACTIONS = setOf(
        ACTION_EINK_FORCE_CLEAR,
        ACTION_EINK_SET_REFRESH_MODE
    )
}
