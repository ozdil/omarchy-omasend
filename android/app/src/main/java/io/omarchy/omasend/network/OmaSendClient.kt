package io.omarchy.omasend.network

import android.content.Context
import io.omarchy.omasend.model.ClipboardPayload
import io.omarchy.omasend.model.TransferDecision
import io.omarchy.omasend.model.TransferFileInfo
import io.omarchy.omasend.model.TransferRequest
import io.omarchy.omasend.model.TransferResponse
import kotlinx.coroutines.delay
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import java.io.InputStream
import java.net.URLEncoder
import java.util.concurrent.TimeUnit

class OmaSendClient(private val context: Context) {
    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }
    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .build()

    fun sendTransferRequest(
        targetIp: String,
        targetPort: Int,
        files: List<TransferFileInfo>
    ): Result<String> {
        return try {
            val totalBytes = files.sumOf { it.size_bytes }
            val requestPayload = TransferRequest(
                sender_id = NetworkUtils.getDeviceId(context),
                sender_name = NetworkUtils.getDeviceName(context),
                sender_ip = NetworkUtils.getLocalIpAddress(),
                files = files,
                total_size_bytes = totalBytes
            )
            val jsonBody = json.encodeToString(TransferRequest.serializer(), requestPayload)
            val request = Request.Builder()
                .url("http://$targetIp:$targetPort/api/p2p/request")
                .post(jsonBody.toRequestBody("application/json".toMediaType()))
                .build()

            val response = client.newCall(request).execute()
            val respBody = response.body?.string() ?: return Result.failure(Exception("Empty response"))
            val transferResp = json.decodeFromString<TransferResponse>(respBody)

            if (transferResp.token != null) {
                Result.success(transferResp.token)
            } else {
                Result.failure(Exception(transferResp.error ?: "Peer rejected transfer request"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun pollDecision(
        targetIp: String,
        targetPort: Int,
        token: String,
        timeoutSec: Int = 30
    ): Result<Boolean> {
        val deadline = System.currentTimeMillis() + (timeoutSec * 1000L)
        while (System.currentTimeMillis() < deadline) {
            try {
                val request = Request.Builder()
                    .url("http://$targetIp:$targetPort/api/p2p/decision?token=$token")
                    .get()
                    .build()

                val response = client.newCall(request).execute()
                val respBody = response.body?.string() ?: ""
                val decision = json.decodeFromString<TransferDecision>(respBody)

                when (decision.status) {
                    "ACCEPTED" -> return Result.success(true)
                    "REJECTED" -> return Result.failure(Exception("Transfer was declined by recipient."))
                    "EXPIRED" -> return Result.failure(Exception("Transfer request expired."))
                    else -> {
                        // Still PENDING, wait and poll again
                    }
                }
            } catch (_: Exception) {
            }
            delay(600)
        }
        return Result.failure(Exception("Transfer timed out waiting for approval."))
    }

    fun uploadFileStream(
        targetIp: String,
        targetPort: Int,
        token: String,
        filename: String,
        totalBytes: Long,
        inputStream: InputStream,
        onProgress: (bytesWritten: Long, totalBytes: Long, percent: Int) -> Unit
    ): Result<Unit> {
        return try {
            val encodedName = URLEncoder.encode(filename, "UTF-8")
            val countingBody = object : RequestBody() {
                override fun contentType() = "application/octet-stream".toMediaType()
                override fun contentLength() = totalBytes

                override fun writeTo(sink: BufferedSink) {
                    val buffer = ByteArray(65536)
                    var uploaded = 0L
                    var read: Int
                    while (inputStream.read(buffer).also { read = it } != -1) {
                        sink.write(buffer, 0, read)
                        uploaded += read
                        val percent = if (totalBytes > 0) ((uploaded * 100) / totalBytes).toInt() else 0
                        onProgress(uploaded, totalBytes, percent)
                    }
                }
            }

            val request = Request.Builder()
                .url("http://$targetIp:$targetPort/api/p2p/upload?token=$token&filename=$encodedName")
                .post(countingBody)
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                Result.success(Unit)
            } else {
                Result.failure(Exception("Upload failed with HTTP ${response.code}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try {
                inputStream.close()
            } catch (_: Exception) {
            }
        }
    }

    fun sendClipboard(
        targetIp: String,
        targetPort: Int,
        text: String
    ): Result<Unit> {
        return try {
            val payload = ClipboardPayload(
                sender_id = NetworkUtils.getDeviceId(context),
                sender_name = NetworkUtils.getDeviceName(context),
                text = text
            )
            val jsonBody = json.encodeToString(ClipboardPayload.serializer(), payload)
            val request = Request.Builder()
                .url("http://$targetIp:$targetPort/api/p2p/clipboard")
                .post(jsonBody.toRequestBody("application/json".toMediaType()))
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                Result.success(Unit)
            } else {
                Result.failure(Exception("Clipboard sync failed with HTTP ${response.code}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
