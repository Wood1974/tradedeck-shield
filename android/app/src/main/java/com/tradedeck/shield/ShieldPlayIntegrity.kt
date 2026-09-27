package com.tradedeck.shield

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Section 4: Google Play Integrity Standard API client.
 *
 * The requestHash must be the Shield bind hash for the capture. The encrypted
 * token is sent to Shield; the server asks Google to decode it and verifies the
 * returned package name, requestHash, timestamp, app and device verdicts.
 */
class ShieldPlayIntegrityClient(context: Context, private val cloudProjectNumber: Long) {
    private val manager = IntegrityManagerFactory.createStandard(context.applicationContext)
    @Volatile private var provider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

    suspend fun prepare() {
        require(cloudProjectNumber > 0) { "SHIELD_CLOUD_PROJECT_NUMBER is not configured" }
        suspendCancellableCoroutine<Unit> { cont ->
            manager.prepareIntegrityToken(
                StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
                    .setCloudProjectNumber(cloudProjectNumber)
                    .build()
            ).addOnSuccessListener { result ->
                provider = result
                cont.resume(Unit)
            }.addOnFailureListener { error ->
                cont.resumeWithException(error)
            }
        }
    }

    suspend fun requestToken(requestHash: String): String {
        require(requestHash.isNotBlank()) { "requestHash is required" }
        if (provider == null) prepare()
        return suspendCancellableCoroutine { cont ->
            provider!!.request(
                StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
                    .setRequestHash(requestHash)
                    .build()
            ).addOnSuccessListener { token ->
                cont.resume(token.token())
            }.addOnFailureListener { error ->
                cont.resumeWithException(error)
            }
        }
    }
}
