package com.tradedeck.shield

import android.location.Location
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.DataOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID

data class ShieldSession(val token: String, val accountId: String)
data class ShieldChallenge(val nonce: String, val pointId: String)

class ShieldApi(private val base: String) {
    init { require(base.startsWith("https://")) { "Shield requires an HTTPS API URL" } }

    private fun connection(path: String, method: String, token: String? = null): HttpURLConnection {
        val result = URL(base.trimEnd('/') + path).openConnection() as HttpURLConnection
        result.requestMethod = method
        result.connectTimeout = 10000
        result.readTimeout = 20000
        result.doInput = true
        if (token != null) result.setRequestProperty("Authorization", "Bearer $token")
        return result
    }

    private fun response(connection: HttpURLConnection): JSONObject {
        try {
            val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
            val content = stream?.bufferedReader()?.use { it.readText() } ?: ""
            if (connection.responseCode !in 200..299) throw IllegalStateException("Shield HTTP ${connection.responseCode}: $content")
            return JSONObject(content)
        } finally { connection.disconnect() }
    }

    suspend fun login(email: String, password: String): ShieldSession = withContext(Dispatchers.IO) {
        val c = connection("/shield/auth/login", "POST")
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/json")
        c.outputStream.use { it.write(JSONObject().put("email",email).put("password",password).toString().toByteArray(Charsets.UTF_8)) }
        val json = response(c)
        ShieldSession(json.getString("access_token"), json.getString("account_id"))
    }

    suspend fun challenge(session: ShieldSession, jobId: String, pointId: String): ShieldChallenge = withContext(Dispatchers.IO) {
        val c = connection("/shield/jobs/${URLEncoder.encode(jobId,"UTF-8")}/challenge", "POST", session.token)
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
        c.outputStream.use { it.write("point_id=${URLEncoder.encode(pointId,"UTF-8")}".toByteArray(Charsets.UTF_8)) }
        val json = response(c)
        ShieldChallenge(json.getString("nonce"), json.getString("point_id"))
    }

    suspend fun capture(session: ShieldSession, jobId: String, challenge: ShieldChallenge,
                        originalJpeg: ByteArray, capturedAt: Instant, locationStated: String, purpose: String,
                        locationFix: Location?,
                        integrityClient: ShieldPlayIntegrityClient): String = withContext(Dispatchers.IO) {
        val location = locationStated.trim()
        val why = purpose.trim()
        ShieldAttestationSheet(location,why).validate()
        val note = "{\"location_stated\":${JSONObject.quote(location)},\"purpose\":${JSONObject.quote(why)}}"
        val photoHash = sha256(originalJpeg)
        val noteHash = sha256(note.toByteArray(Charsets.UTF_8))
        val bind = sha256((photoHash + noteHash + jobId + challenge.pointId + challenge.nonce + session.accountId).toByteArray(Charsets.UTF_8))
        val playToken = integrityClient.requestToken(bind)
        val boundary = "Shield-${UUID.randomUUID()}"
        val c = connection("/shield/jobs/${URLEncoder.encode(jobId,"UTF-8")}/photos", "POST", session.token)
        c.doOutput = true
        c.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
        DataOutputStream(c.outputStream).use { out ->
            fun field(name: String, value: String) {
                out.write("--$boundary\r\nContent-Disposition: form-data; name=\"$name\"\r\n\r\n$value\r\n".toByteArray(Charsets.UTF_8))
            }
            field("point_id",challenge.pointId)
            field("nonce",challenge.nonce)
            field("location_stated",location)
            field("purpose",why)
            field("captured_at",capturedAt.toString())
            if (locationFix != null) {
                field("lat",locationFix.latitude.toString())
                field("lng",locationFix.longitude.toString())
                if (locationFix.hasAccuracy()) field("accuracy_m",locationFix.accuracy.toString())
                field("location_observed_at",Instant.ofEpochMilli(locationFix.time).toString())
                field("mock_flag",locationFix.isFromMockProvider.toString())
            }
            field("play_integrity_token",playToken)
            out.write("--$boundary\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"capture.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n".toByteArray(Charsets.UTF_8))
            out.write(originalJpeg)
            out.write("\r\n--$boundary--\r\n".toByteArray(Charsets.UTF_8))
        }
        response(c).getString("evidence_id")
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
