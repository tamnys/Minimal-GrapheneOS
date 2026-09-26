package com.lmqr.hMP01_comp_service

import android.content.SharedPreferences
import com.lmqr.hMP01_comp_service.command_runners.CommandRunner
import java.lang.reflect.Proxy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MP01ControlResultTest {
    private class Runner(var succeeds: Boolean) : CommandRunner {
        val commands = mutableListOf<List<String>>()

        override fun runCommands(cmds: Array<String>): Boolean {
            commands += cmds.toList()
            return succeeds
        }

        override fun onDestroy() = Unit
    }

    private fun preferences(mode: String? = null, wrongType: Boolean = false): SharedPreferences =
        Proxy.newProxyInstance(
            SharedPreferences::class.java.classLoader,
            arrayOf(SharedPreferences::class.java)
        ) { _, method, args ->
            when (method.name) {
                "getString" -> if (wrongType) throw ClassCastException("legacy preference") else mode
                "getInt", "getBoolean" -> args!![1]
                else -> error("Unexpected SharedPreferences call: ${method.name}")
            }
        } as SharedPreferences

    @Test
    fun refreshPreferenceFallbackPreservesValidModes() {
        assertEquals(RefreshMode.BALANCED.mode, parseDefaultRefreshMode("1"))
        assertEquals(RefreshMode.SMOOTH.mode, parseDefaultRefreshMode("2"))
        assertEquals(RefreshMode.SPEED.mode, parseDefaultRefreshMode("3"))
        assertEquals(RefreshMode.SPEED.mode, parseDefaultRefreshMode(null))
        assertEquals(RefreshMode.SPEED.mode, parseDefaultRefreshMode("invalid"))
    }

    @Test
    fun malformedOrWrongTypePreferenceDoesNotCrashInitialization() {
        val runner = Runner(true)
        assertEquals(RefreshMode.SPEED, RefreshModeManager(preferences("invalid"), runner).currentMode)
        assertEquals(RefreshMode.SPEED, RefreshModeManager(preferences(wrongType = true), runner).currentMode)
        assertEquals(RefreshMode.SMOOTH, RefreshModeManager(preferences("2"), runner).currentMode)
    }

    @Test
    fun failedHardwareCommandsAreReturnedAndReported() {
        val runner = Runner(false)
        val failures = mutableListOf<String>()
        val brightness = BrightnessManager(preferences(), runner, failures::add)
        assertFalse(brightness.applyBrightness())
        assertFalse(brightness.turnOffBrightness())
        assertEquals(listOf("br_co64", "br_wm64", "br_kb64"), runner.commands[0])
        assertEquals(listOf("br_co0", "br_wm0", "br_kb0"), runner.commands[1])

        val refresh = RefreshModeManager(preferences("1"), runner, failures::add)
        assertFalse(refresh.applyMode())
        assertEquals(RefreshMode.BALANCED, refresh.currentMode)
        assertTrue(failures.any { it.contains("saved brightness") })
        assertTrue(failures.any { it.contains("backlights") })
        assertTrue(failures.any { it.contains("refresh mode BALANCED") })

        runner.succeeds = true
        failures.clear()
        assertTrue(brightness.applyBrightness())
        assertTrue(refresh.applyMode())
        assertTrue(failures.isEmpty())
    }
}
