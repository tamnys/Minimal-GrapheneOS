package com.lmqr.hMP01_comp_service.automation

import android.os.Bundle
import android.widget.Toast
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreferenceCompat
import com.lmqr.hMP01_comp_service.R
import java.text.DateFormat
import java.util.Date

class EinkAutomationSettingsFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        rebuildScreen()
    }

    override fun onResume() {
        super.onResume()
        requireActivity().title = getString(R.string.eink_automation_title)
        rebuildScreen()
    }

    private fun rebuildScreen() {
        val context = requireContext()
        val screen = preferenceManager.createPreferenceScreen(context)
        val requesters = EinkAutomationAuthorizer.findRequestingApps(context)

        if (requesters.isEmpty()) {
            screen.addPreference(
                Preference(context).apply {
                    title = getString(R.string.eink_automation_no_requesters_title)
                    summary = getString(R.string.eink_automation_no_requesters_summary)
                    isSelectable = false
                }
            )
        }

        requesters.forEach { app ->
            screen.addPreference(
                SwitchPreferenceCompat(context).apply {
                    key = "eink_automation.${app.packageName}"
                    title = app.label
                    summary = app.summary()
                    isChecked = app.allowed
                    setOnPreferenceChangeListener { _, newValue ->
                        val shouldAllow = newValue == true
                        val success = if (shouldAllow) {
                            EinkAutomationAuthorizer.allow(context, app.packageName)
                        } else {
                            EinkAutomationAuthorizer.revoke(context, app.packageName)
                            true
                        }

                        if (!success) {
                            Toast
                                .makeText(
                                    context,
                                    R.string.eink_automation_allow_failed,
                                    Toast.LENGTH_SHORT
                                )
                                .show()
                            false
                        } else {
                            view?.post { rebuildScreen() }
                            true
                        }
                    }
                }
            )
        }

        preferenceScreen = screen
    }

    private fun EinkAutomationAuthorizer.RequestingApp.summary(): String =
        buildString {
            append("Package: ")
            append(packageName)
            append("\nStatus: ")
            append(
                getString(
                    if (allowed)
                        R.string.eink_automation_allowed
                    else
                        R.string.eink_automation_not_allowed
                )
            )
            append("\nLast used: ")
            append(formatTime(lastUsedMillis))
            if (lastDeniedMillis > 0L) {
                append("\nLast denied: ")
                append(formatTime(lastDeniedMillis))
                if (!lastDeniedReason.isNullOrBlank()) {
                    append(" (")
                    append(lastDeniedReason)
                    append(")")
                }
            }
        }

    private fun formatTime(millis: Long): String {
        if (millis <= 0L)
            return getString(R.string.eink_automation_never)
        return DateFormat
            .getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
            .format(Date(millis))
    }
}
