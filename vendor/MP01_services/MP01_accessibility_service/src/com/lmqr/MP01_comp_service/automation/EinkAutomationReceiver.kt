package com.lmqr.hMP01_comp_service.automation

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import com.lmqr.hMP01_comp_service.command_runners.Commands
import com.lmqr.hMP01_comp_service.command_runners.UnixSocketCommandRunner
import java.util.Locale

class EinkAutomationReceiver : BroadcastReceiver() {
    @SuppressLint("NewApi")
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            Log.w(TAG, "Denied e-ink automation action=$action reason=sender identity unavailable")
            return
        }

        val senderUid = getSentFromUid()
        val senderPackageName = getSentFromPackage()
        val command = when (action) {
            EinkAutomationContract.ACTION_EINK_FORCE_CLEAR -> Commands.FORCE_CLEAR
            EinkAutomationContract.ACTION_EINK_SET_REFRESH_MODE ->
                commandForMode(intent.getStringExtra(EinkAutomationContract.EXTRA_REFRESH_MODE))
                    ?: run {
                        EinkAutomationAuthorizer.recordDeniedForSender(
                            context,
                            senderPackageName,
                            senderUid,
                            "invalid refresh mode"
                        )
                        return
                    }
            else -> {
                EinkAutomationAuthorizer.recordDeniedForSender(
                    context,
                    senderPackageName,
                    senderUid,
                    "unsupported action"
                )
                return
            }
        }

        val authorization = EinkAutomationAuthorizer.authorize(
            context,
            senderPackageName,
            senderUid,
            action
        )
        if (!authorization.accepted)
            return

        val commandRunner = UnixSocketCommandRunner()
        try {
            if (!commandRunner.runCommands(arrayOf(command)))
                Log.e(TAG, "Failed to deliver authorized e-ink automation action=$action")
        } finally {
            commandRunner.onDestroy()
        }
    }

    private fun commandForMode(rawMode: String?): String? =
        when (rawMode?.trim()?.lowercase(Locale.US)) {
            EinkAutomationContract.MODE_BALANCED -> Commands.SPEED_BALANCED
            EinkAutomationContract.MODE_SMOOTH -> Commands.SPEED_SMOOTH
            EinkAutomationContract.MODE_SPEED -> Commands.SPEED_FAST
            else -> null
        }

    private companion object {
        const val TAG = "EinkAutomationReceiver"
    }
}
