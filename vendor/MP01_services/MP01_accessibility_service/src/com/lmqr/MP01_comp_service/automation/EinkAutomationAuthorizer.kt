package com.lmqr.hMP01_comp_service.automation

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.SystemClock
import android.util.Log
import java.security.MessageDigest
import java.util.Locale

object EinkAutomationAuthorizer {
    private const val TAG = "EinkAutomation"
    private const val PREFS_NAME = "eink_automation"
    private const val FORCE_CLEAR_RATE_LIMIT_MS = 2_000L
    private const val REFRESH_MODE_RATE_LIMIT_MS = 500L

    data class RequestingApp(
        val packageName: String,
        val label: String,
        val certificateSha256: String?,
        val allowed: Boolean,
        val lastUsedMillis: Long,
        val lastDeniedMillis: Long,
        val lastDeniedReason: String?
    )

    data class AuthorizationResult(
        val accepted: Boolean,
        val packageName: String?,
        val reason: String?
    )

    fun findRequestingApps(context: Context): List<RequestingApp> {
        val pm = context.packageManager
        val prefs = prefs(context)
        return installedPackages(pm)
            .filter {
                it.requestedPermissions?.contains(
                    EinkAutomationContract.PERMISSION_CONTROL_EINK_REFRESH
                ) == true
            }
            .map { packageInfo ->
                val packageName = packageInfo.packageName
                val certificateSha256 = signingCertificateSha256(packageInfo)
                RequestingApp(
                    packageName = packageName,
                    label = labelFor(pm, packageInfo),
                    certificateSha256 = certificateSha256,
                    allowed = isApproved(prefs, packageName, certificateSha256),
                    lastUsedMillis = prefs.getLong(lastUsedKey(packageName), 0L),
                    lastDeniedMillis = prefs.getLong(lastDeniedKey(packageName), 0L),
                    lastDeniedReason = prefs.getString(lastDeniedReasonKey(packageName), null)
                )
            }
            .sortedWith(
                compareBy<RequestingApp> { it.label.lowercase(Locale.US) }
                    .thenBy { it.packageName }
            )
    }

    @Synchronized
    fun allow(context: Context, packageName: String): Boolean {
        val packageInfo = packageInfoFor(
            context.packageManager,
            packageName,
            PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
        ) ?: return false
        if (
            packageInfo.requestedPermissions?.contains(
                EinkAutomationContract.PERMISSION_CONTROL_EINK_REFRESH
            ) != true
        )
            return false

        val certificateSha256 = signingCertificateSha256(packageInfo)
            ?: return false
        prefs(context)
            .edit()
            .putBoolean(allowedKey(packageName), true)
            .putString(certKey(packageName), certificateSha256)
            .remove(lastDeniedReasonKey(packageName))
            .apply()
        Log.i(TAG, "Approved e-ink automation for $packageName")
        return true
    }

    @Synchronized
    fun revoke(context: Context, packageName: String) {
        clearApproval(context, packageName)
        Log.i(TAG, "Revoked e-ink automation for $packageName")
    }

    @Synchronized
    fun authorize(
        context: Context,
        sentPackageName: String?,
        sentUid: Int,
        action: String
    ): AuthorizationResult {
        val sender = identifySender(context, sentPackageName, sentUid)
            ?: return deny(context, null, "sender not identified")
        val packageName = sender.packageName
        val pm = context.packageManager

        if (action !in EinkAutomationContract.PUBLIC_ACTIONS)
            return deny(context, packageName, "unsupported action")

        if (
            pm.checkPermission(
                EinkAutomationContract.PERMISSION_CONTROL_EINK_REFRESH,
                packageName
            ) != PackageManager.PERMISSION_GRANTED
        )
            return deny(context, packageName, "permission not granted")

        val currentCertificateSha256 = currentSigningCertificateSha256(context, packageName)
            ?: return deny(context, packageName, "signing certificate unavailable")
        val prefs = prefs(context)
        if (!prefs.getBoolean(allowedKey(packageName), false))
            return deny(context, packageName, "not approved in settings")

        val approvedCertificateSha256 = prefs.getString(certKey(packageName), null)
        if (approvedCertificateSha256 != currentCertificateSha256) {
            clearApproval(context, packageName)
            return deny(context, packageName, "signing certificate changed")
        }

        val rateLimitKey = rateLimitKey(action, sentUid)
        val rateLimitWindowMs = when (action) {
            EinkAutomationContract.ACTION_EINK_FORCE_CLEAR -> FORCE_CLEAR_RATE_LIMIT_MS
            else -> REFRESH_MODE_RATE_LIMIT_MS
        }
        val nowElapsedMs = SystemClock.elapsedRealtime()
        val lastAcceptedElapsedMs = prefs.getLong(rateLimitKey, Long.MIN_VALUE)
        if (
            lastAcceptedElapsedMs != Long.MIN_VALUE &&
            lastAcceptedElapsedMs <= nowElapsedMs &&
            nowElapsedMs - lastAcceptedElapsedMs < rateLimitWindowMs
        )
            return deny(context, packageName, "rate limited")

        prefs.edit()
            .putLong(rateLimitKey, nowElapsedMs)
            .putLong(lastUsedKey(packageName), System.currentTimeMillis())
            .remove(lastDeniedReasonKey(packageName))
            .apply()
        Log.i(TAG, "Accepted e-ink automation action=$action package=$packageName uid=$sentUid")
        return AuthorizationResult(true, packageName, null)
    }

    fun recordDeniedForSender(
        context: Context,
        sentPackageName: String?,
        sentUid: Int,
        reason: String
    ) {
        val packageName = identifySender(context, sentPackageName, sentUid)?.packageName
        recordDenied(context, packageName, reason)
        Log.w(TAG, "Denied e-ink automation package=${packageName ?: "unknown"} reason=$reason")
    }

    private data class Sender(val packageName: String)

    private fun identifySender(
        context: Context,
        sentPackageName: String?,
        sentUid: Int
    ): Sender? {
        if (sentUid < 0)
            return null

        val packagesForUid = context.packageManager.getPackagesForUid(sentUid)
            ?.toSet()
            ?.takeIf { it.isNotEmpty() }
            ?: return null

        val packageName = if (!sentPackageName.isNullOrBlank()) {
            if (sentPackageName !in packagesForUid)
                return null
            sentPackageName
        } else {
            if (packagesForUid.size != 1)
                return null
            packagesForUid.first()
        }
        return Sender(packageName)
    }

    private fun deny(
        context: Context,
        packageName: String?,
        reason: String
    ): AuthorizationResult {
        recordDenied(context, packageName, reason)
        Log.w(TAG, "Denied e-ink automation package=${packageName ?: "unknown"} reason=$reason")
        return AuthorizationResult(false, packageName, reason)
    }

    private fun recordDenied(context: Context, packageName: String?, reason: String) {
        if (packageName == null)
            return
        prefs(context).edit()
            .putLong(lastDeniedKey(packageName), System.currentTimeMillis())
            .putString(lastDeniedReasonKey(packageName), reason)
            .apply()
    }

    private fun clearApproval(context: Context, packageName: String) {
        prefs(context).edit()
            .remove(allowedKey(packageName))
            .remove(certKey(packageName))
            .apply()
    }

    private fun isApproved(
        prefs: android.content.SharedPreferences,
        packageName: String,
        currentCertificateSha256: String?
    ): Boolean =
        currentCertificateSha256 != null &&
            prefs.getBoolean(allowedKey(packageName), false) &&
            prefs.getString(certKey(packageName), null) == currentCertificateSha256

    private fun currentSigningCertificateSha256(
        context: Context,
        packageName: String
    ): String? =
        packageInfoFor(context.packageManager, packageName)?.let { signingCertificateSha256(it) }

    private fun signingCertificateSha256(packageInfo: PackageInfo): String? {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = packageInfo.signingInfo ?: return null
            val currentSigners = signingInfo.apkContentsSigners ?: emptyArray()
            if (currentSigners.isNotEmpty())
                currentSigners
            else
                signingInfo.signingCertificateHistory ?: emptyArray()
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures ?: emptyArray()
        }

        if (signatures.isEmpty())
            return null

        return signatures
            .map { sha256(it) }
            .sorted()
            .joinToString(";")
    }

    private fun sha256(signature: Signature): String {
        val digest = MessageDigest
            .getInstance("SHA-256")
            .digest(signature.toByteArray())
        return digest.joinToString(":") {
            "%02X".format(Locale.US, it.toInt() and 0xff)
        }
    }

    private fun installedPackages(pm: PackageManager): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(flags)
        }
    }

    private fun packageInfoFor(
        pm: PackageManager,
        packageName: String,
        flags: Int = PackageManager.GET_SIGNING_CERTIFICATES
    ): PackageInfo? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, flags)
            }
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }

    private fun labelFor(pm: PackageManager, packageInfo: PackageInfo): String =
        try {
            packageInfo.applicationInfo?.loadLabel(pm)?.toString() ?: packageInfo.packageName
        } catch (e: RuntimeException) {
            packageInfo.packageName
        }

    private fun prefs(context: Context) =
        context
            .createDeviceProtectedStorageContext()
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun allowedKey(packageName: String) = "allowed.$packageName"
    private fun certKey(packageName: String) = "cert.$packageName"
    private fun lastUsedKey(packageName: String) = "last_used.$packageName"
    private fun lastDeniedKey(packageName: String) = "last_denied.$packageName"
    private fun lastDeniedReasonKey(packageName: String) = "last_denied_reason.$packageName"
    private fun rateLimitKey(action: String, uid: Int) = "rate.$action.$uid"
}
