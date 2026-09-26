package com.lmqr.hMP01_comp_service

import android.content.SharedPreferences
import android.util.Log
import android.widget.SeekBar
import com.lmqr.hMP01_comp_service.command_runners.CommandRunner

/**
 * Manages brightness settings and their persistence
 */
class BrightnessManager(
    private val sharedPreferences: SharedPreferences,
    private val commandRunner: CommandRunner,
    private val reportFailure: (String) -> Unit = { Log.e("MP01Brightness", it) }
) {
    companion object {
        private const val PREF_COLD_BRIGHTNESS = "cold_brightness_value"
        private const val PREF_WARM_BRIGHTNESS = "warm_brightness_value"
        private const val PREF_KEYBOARD_BRIGHTNESS = "keyboard_brightness_value"
    }

    var coldBrightness: Int
        get() = sharedPreferences.getInt(PREF_COLD_BRIGHTNESS, 64)
        set(value) {
            sharedPreferences.edit().putInt(PREF_COLD_BRIGHTNESS, value).apply()
        }

    var warmBrightness: Int
        get() = sharedPreferences.getInt(PREF_WARM_BRIGHTNESS, 64)
        set(value) {
            sharedPreferences.edit().putInt(PREF_WARM_BRIGHTNESS, value).apply()
        }
    var keyboardBrightness: Int
        get() = sharedPreferences.getInt(PREF_KEYBOARD_BRIGHTNESS, 64)
        set(value) {
            sharedPreferences.edit().putInt(PREF_KEYBOARD_BRIGHTNESS, value).apply()
        }
    /**
     * Apply current brightness settings to the device
     */
    fun applyBrightness(): Boolean = runHardwareCommands(
        arrayOf("br_co${coldBrightness}", "br_wm${warmBrightness}", "br_kb${keyboardBrightness}"),
        "apply saved brightness"
    )

    /**
     * Update both brightness values and apply them
     */
    fun setBrightness(coldValue: Int, warmValue: Int, keyboardValue: Int): Boolean {
        coldBrightness = coldValue
        warmBrightness = warmValue
        keyboardBrightness = keyboardValue
        return applyBrightness()
    }

    /**
     * Turn off both backlights
     */
    fun turnOffBrightness(): Boolean = runHardwareCommands(
        arrayOf("br_co0", "br_wm0", "br_kb0"),
        "turn off backlights"
    )

    private fun runHardwareCommands(commands: Array<String>, operation: String): Boolean {
        val applied = commandRunner.runCommands(commands)
        if (!applied) reportFailure("Failed to $operation")
        return applied
    }

    /**
     * Configure seekbars with current brightness values and listeners
     */
    fun setupSeekBars(lightSeekbar: SeekBar, lightWarmSeekbar: SeekBar, lightKeyboardSeekbar: SeekBar) {
        lightSeekbar.min = 0
        lightSeekbar.max = 80
        lightSeekbar.progress = coldBrightness
        lightSeekbar.setOnSeekBarChangeListener(
            object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                    if (fromUser) {
                        runHardwareCommands(arrayOf("br_co$progress"), "set cold frontlight")
                    }
                }

                override fun onStartTrackingTouch(seekBar: SeekBar?) {}

                override fun onStopTrackingTouch(seekBar: SeekBar?) {
                    coldBrightness = seekBar?.progress ?: 0
                }
            }
        )

        lightWarmSeekbar.min = 0
        lightWarmSeekbar.max = 254
        lightWarmSeekbar.progress = warmBrightness
        lightWarmSeekbar.setOnSeekBarChangeListener(
            object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                    if (fromUser) {
                        runHardwareCommands(arrayOf("br_wm$progress"), "set warm frontlight")
                    }
                }

                override fun onStartTrackingTouch(seekBar: SeekBar?) {}

                override fun onStopTrackingTouch(seekBar: SeekBar?) {
                    warmBrightness = seekBar?.progress ?: 0
                }
            }
        )
        lightKeyboardSeekbar.min = 0
        lightKeyboardSeekbar.max = 254
        lightKeyboardSeekbar.progress = keyboardBrightness
        lightKeyboardSeekbar.setOnSeekBarChangeListener(
            object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                    if (fromUser) {
                        runHardwareCommands(arrayOf("br_kb$progress"), "set keyboard backlight")
                    }
                }

                override fun onStartTrackingTouch(seekBar: SeekBar?) {}

                override fun onStopTrackingTouch(seekBar: SeekBar?) {
                    keyboardBrightness = seekBar?.progress ?: 0
                }
            }
        )

    }
}
