/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.os.IBinder
import android.os.Parcel
import android.os.Parcelable
import android.os.ServiceManager
import android.os.ServiceSpecificException
import android.security.Credentials
import android.security.KeyStore
import android.security.keystore.KeystoreResponse
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import kotlin.system.exitProcess

private const val RESTART_RETRY_DELAY_MS = 1000L

abstract class BaseKeystoreInterceptor : BinderInterceptor() {

    protected lateinit var keystore: IBinder
    @Volatile protected var triedCount = 0
    @Volatile protected var injected = false
    protected open val maxRetries: Int = 30

    private val restartLock = Any()
    @Volatile private var reregistering = false

    protected abstract val serviceName: String
    protected abstract val injectionCommand: String
    protected abstract val processName: String

    fun tryRunKeystoreInterceptor(): Boolean {
        Logger.i("Trying to register ${this::class.simpleName} (attempt $triedCount)...")

        val service = getService() ?: return false
        val backdoor = getBinderBackdoor(service)

        return if (backdoor != null) {
            setupInterceptor(service, backdoor)
        } else {
            handleMissingBackdoor()
        }
    }

    protected open fun getService(): IBinder? = ServiceManager.getService(serviceName)

    protected open fun setupInterceptor(service: IBinder, backdoor: IBinder): Boolean {
        Logger.i("Registering for $serviceName: $service")

        if (!registerBinderInterceptor(backdoor, service, this)) {
            Logger.e("Failed to register interceptor for $serviceName; aborting setup")
            return false
        }

        keystore = service
        service.linkToDeath(createDeathRecipient(), 0)
        onInterceptorSetup(service, backdoor)

        return true
    }

    private fun handleMissingBackdoor(): Boolean {
        if (triedCount >= maxRetries) {
            Logger.e("Tried injection $maxRetries times but still no backdoor, exiting")
            exitProcess(1)
        }

        if (!injected) {
            performInjection()
            injected = true
        }

        triedCount++
        return false
    }

    protected open fun performInjection() {
        Logger.i("Attempting to inject into $processName...")

        val command = arrayOf("/system/bin/sh", "-c", injectionCommand)
        Logger.d("Injection command: ${command.joinToString(" ")}")

        val process = Runtime.getRuntime().exec(command)

        if (process.waitFor() != 0) {
            Logger.e("Injection failed! Daemon will exit")
            exitProcess(1)
        }

        Logger.i("Injection completed successfully")
    }

    protected open fun createDeathRecipient(): IBinder.DeathRecipient =
        object : IBinder.DeathRecipient {
            override fun binderDied() {
                Logger.w("$serviceName died; watching for its restart instead of exiting")
                scheduleReregistration()
            }
        }

    /**
     * Re-enters the registration loop in place. The dead service's binder is gone; the next
     * attempts pick up the freshly restarted keystore process (new pid, empty maps), inject again
     * and re-register. Staying alive avoids the old design's cost: a daemon exit meant a JVM cold
     * start plus a fresh probe and property pass, and in that window target apps transacted with
     * the real, unhooked keystore — the exact race that surfaced as probe failures after a
     * keystore2 crash. The shell supervisor remains as the backstop for genuine daemon failures.
     */
    private fun scheduleReregistration() {
        synchronized(restartLock) {
            if (reregistering) return
            reregistering = true
        }
        Thread({
            try {
                // Fresh budget for the fresh process: the counters guard the *startup* path, and
                // leaking them here would give up before the new keystore finishes booting.
                triedCount = 0
                injected = false
                while (!tryRunKeystoreInterceptor()) {
                    Logger.d("Waiting for $serviceName to come back...")
                    Thread.sleep(RESTART_RETRY_DELAY_MS)
                }
                Logger.i("$serviceName re-registered after restart")
            } catch (e: Exception) {
                Logger.e("Re-registration loop failed; falling back to supervisor restart", e)
                exitProcess(0)
            } finally {
                synchronized(restartLock) { reregistering = false }
            }
        }, "tsoss-reregister").apply { isDaemon = true }.start()
    }

    protected open fun onInterceptorSetup(service: IBinder, backdoor: IBinder) {
        // Default implementation does nothing
    }
}

object InterceptorUtils {

    fun getTransactCode(clazz: Class<*>, method: String): Int =
        clazz.getDeclaredField("TRANSACTION_$method").apply { isAccessible = true }.getInt(null)

    fun createSuccessKeystoreResponse(): KeystoreResponse {
        val parcel = Parcel.obtain()
        try {
            parcel.writeInt(KeyStore.NO_ERROR)
            parcel.writeString("")
            parcel.setDataPosition(0)
            return KeystoreResponse.CREATOR.createFromParcel(parcel)
        } finally {
            parcel.recycle()
        }
    }

    fun createSuccessReply(resultCode: Int = KeyStore.NO_ERROR): BinderInterceptor.OverrideReply {
        val parcel = Parcel.obtain()
        parcel.writeNoException()
        parcel.writeInt(resultCode)
        return BinderInterceptor.OverrideReply(0, parcel)
    }

    fun createByteArrayReply(data: ByteArray, resultCode: Int = KeyStore.NO_ERROR): BinderInterceptor.OverrideReply {
        val parcel = Parcel.obtain()
        parcel.writeNoException()
        parcel.writeByteArray(data)
        return BinderInterceptor.OverrideReply(resultCode, parcel)
    }

    fun <T : Parcelable?> createTypedObjectReply(
        obj: T,
        flags: Int = 0,
        resultCode: Int = 0,
    ): BinderInterceptor.OverrideReply {
        val parcel = Parcel.obtain()
        parcel.writeNoException()
        parcel.writeTypedObject(obj, flags)
        return BinderInterceptor.OverrideReply(resultCode, parcel)
    }

    fun typedReply(metadata: Parcelable?): BinderInterceptor.OverrideReply = createTypedObjectReply(metadata)

    fun errorReply(errorCode: Int, message: String): BinderInterceptor.OverrideReply {
        val p = Parcel.obtain()
        p.writeException(ServiceSpecificException(errorCode, message))
        return BinderInterceptor.OverrideReply(0, p)
    }

    fun successReply(): BinderInterceptor.OverrideReply {
        val p = Parcel.obtain()
        p.writeNoException()
        return BinderInterceptor.OverrideReply(0, p)
    }

    fun String.extractAlias(): String =
        sequenceOf(
            Credentials.USER_PRIVATE_KEY,
            Credentials.USER_SECRET_KEY,
            Credentials.USER_CERTIFICATE,
            Credentials.CA_CERTIFICATE,
        ).firstNotNullOfOrNull { prefix ->
            if (startsWith(prefix) && length > prefix.length) substring(prefix.length) else null
        } ?: this

    fun Parcel.hasException(): Boolean {
        return runCatching { readException() }.exceptionOrNull() != null
    }
}
