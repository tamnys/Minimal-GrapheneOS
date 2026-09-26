package com.lmqr.hMP01_comp_service

internal object MP01FrameworkSettings {
    const val MAX_BRIGHTNESS_PROPERTY = "sys.linevibrator_touch"
    const val THEME_CUSTOMIZATION_SETTING = "theme_customization_overlay_packages"

    private val themeStyles = arrayOf(
        "TONAL_SPOT",
        "VIBRANT",
        "RAINBOW",
        "EXPRESSIVE",
        "FRUIT_SALAD",
        "SPRITZ"
    )

    fun resolveThemeStyle(value: String?): String {
        val index = value
            ?.toIntOrNull()
            ?.takeIf { it in themeStyles.indices }
            ?: themeStyles.lastIndex
        return themeStyles[index]
    }

    fun parseMaxBrightness(value: String?): Int? {
        return value?.toIntOrNull()?.takeIf { it in 0..9999 }
    }
}
