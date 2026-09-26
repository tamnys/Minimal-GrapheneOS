package com.lmqr.hMP01_comp_service.button_mapper

import android.content.Context
import android.util.Log
import com.lmqr.hMP01_comp_service.command_runners.CommandRunner
import com.lmqr.hMP01_comp_service.command_runners.Commands
import com.lmqr.hMP01_comp_service.RefreshModeManager
import android.view.WindowManager
import android.view.Gravity
import android.graphics.PixelFormat
import android.os.Handler
import android.os.Looper
import android.view.View
import android.graphics.Color
import android.content.SharedPreferences
import android.graphics.ColorMatrixColorFilter
import android.graphics.Paint
import android.graphics.Canvas
import android.graphics.PorterDuff
import android.graphics.PorterDuff.Mode

class ClearScreenButtonAction(private val commandRunner: CommandRunner, private val refreshModeManager: RefreshModeManager) : ButtonAction {
    override fun execute(context: Context) {
        if (!commandRunner.runCommands(arrayOf(Commands.FORCE_CLEAR))) {
            Log.e("MP01ClearScreen", "Failed to clear e-ink screen from refresh button")
        }
    }
}
