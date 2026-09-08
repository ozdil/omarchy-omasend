package io.omarchy.omasend.network

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import io.omarchy.omasend.model.ClipboardPayload
import io.omarchy.omasend.model.IncomingTransferPrompt
import io.omarchy.omasend.model.TransferRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class OmaSendServer(private val context: Context) {
    private val scope = CoroutineScope(Dispatchers.IO)
    private var serverJob: Job? = null
    private var serverSocket: ServerSocket? = null
    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    // Token -> PendingTransfer
    data class PendingState(
        val prompt: IncomingTransferPrompt,
        val expiresAt: Long,
        var status: String // "PENDING", "ACCEPTED", "REJECTED"
    )

    private val pendingTransfers = ConcurrentHashMap<String, PendingState>()

    var onIncomingTransferPrompt: ((IncomingTransferPrompt) -> Unit)? = null
    var onClipboardReceived: ((senderName: String, text: String) -> Unit)? = null
    var onFileReceived: ((filename: String, sizeBytes: Long) -> Unit)? = null

    fun acceptTransfer(token: String) {
        pendingTransfers[token]?.status = "ACCEPTED"
    }

    fun rejectTransfer(token: String) {
        pendingTransfers[token]?.status = "REJECTED"
    }

    fun start() {
        if (serverJob != null && serverJob?.isActive == true) return
        serverJob = scope.launch {
            try {
                serverSocket = ServerSocket(NetworkUtils.PORT).apply {
                    reuseAddress = true
                }

                while (isActive) {
                    try {
                        val clientSocket = serverSocket?.accept() ?: break
                        scope.launch {
                            handleClient(clientSocket)
                        }
                    } catch (_: Exception) {
                        break
                    }
                }
            } catch (_: Exception) {
            } finally {
                stop()
            }
        }
    }

    fun stop() {
        serverJob?.cancel()
        serverJob = null
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        serverSocket = null
    }

    private fun handleClient(socket: Socket) {
        try {
            socket.soTimeout = 30000
            val input = BufferedInputStream(socket.getInputStream())
            val output = socket.getOutputStream()

            // Read HTTP headers
            val headerBytes = ByteArrayOutputStream()
            var prev1 = -1
            var prev2 = -1
            var prev3 = -1
            var curr: Int

            while (input.read().also { curr = it } != -1) {
                headerBytes.write(curr)
                if (prev3 == '\r'.code && prev2 == '\n'.code && prev1 == '\r'.code && curr == '\n'.code) {
                    break
                }
                prev3 = prev2
                prev2 = prev1
                prev1 = curr
            }

            val headerStr = headerBytes.toString("UTF-8")
            val lines = headerStr.split("\r\n")
            if (lines.isEmpty()) {
                socket.close()
                return
            }

            val requestLine = lines[0].split(" ")
            if (requestLine.size < 2) {
                socket.close()
                return
            }

            val method = requestLine[0]
            val fullPath = requestLine[1]
            val path = if (fullPath.contains("?")) fullPath.substringBefore("?") else fullPath
            val query = if (fullPath.contains("?")) fullPath.substringAfter("?") else ""

            val headers = mutableMapOf<String, String>()
            for (i in 1 until lines.size) {
                val line = lines[i]
                val colon = line.indexOf(':')
                if (colon != -1) {
                    val key = line.substring(0, colon).trim().lowercase()
                    val value = line.substring(colon + 1).trim()
                    headers[key] = value
                }
            }

            val contentLength = headers["content-length"]?.toLongOrNull() ?: 0L

            when {
                path == "/api/status" || path == "/api/p2p/ping" -> {
                    handlePing(output)
                }
                method == "POST" && path == "/api/p2p/request" -> {
                    handleTransferRequest(input, output, contentLength)
                }
                method == "GET" && path == "/api/p2p/decision" -> {
                    handleDecisionQuery(output, query)
                }
                method == "POST" && path == "/api/p2p/upload" -> {
                    handleFileUpload(input, output, query, contentLength)
                }
                method == "POST" && path == "/api/p2p/clipboard" -> {
                    handleClipboard(input, output, contentLength)
                }
                else -> {
                    sendResponse(output, 404, "Not Found", "application/json", "{\"error\":\"Not found\"}")
                }
            }
        } catch (_: Exception) {
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun handlePing(output: OutputStream) {
        val resp = """
            {
                "status": "OK",
                "id": "${NetworkUtils.getDeviceId(context)}",
                "name": "${NetworkUtils.getDeviceName(context)}",
                "mode": "ALL"
            }
        """.trimIndent()
        sendResponse(output, 200, "OK", "application/json", resp)
    }

    private fun handleTransferRequest(input: InputStream, output: OutputStream, contentLength: Long) {
        if (contentLength > 1024 * 1024) {
            sendResponse(output, 400, "Bad Request", "application/json", "{\"error\":\"Payload too large\"}")
            return
        }
        val bodyBytes = ByteArray(contentLength.toInt())
        var totalRead = 0
        while (totalRead < bodyBytes.size) {
            val r = input.read(bodyBytes, totalRead, bodyBytes.size - totalRead)
            if (r == -1) break
            totalRead += r
        }

        try {
            val bodyJson = String(bodyBytes, Charsets.UTF_8)
            val req = json.decodeFromString<TransferRequest>(bodyJson)
            val token = UUID.randomUUID().toString().replace("-", "")

            val prompt = IncomingTransferPrompt(
                token = token,
                senderId = req.sender_id,
                senderName = req.sender_name,
                senderIp = req.sender_ip,
                files = req.files,
                totalSizeBytes = req.total_size_bytes
            )

            pendingTransfers[token] = PendingState(
                prompt = prompt,
                expiresAt = System.currentTimeMillis() + 30000,
                status = "PENDING"
            )

            Handler(Looper.getMainLooper()).post {
                onIncomingTransferPrompt?.invoke(prompt)
            }

            val resp = """{"status":"PENDING","token":"$token"}"""
            sendResponse(output, 200, "OK", "application/json", resp)
        } catch (e: Exception) {
            sendResponse(output, 400, "Bad Request", "application/json", "{\"error\":\"Invalid request\"}")
        }
    }

    private fun handleDecisionQuery(output: OutputStream, query: String) {
        val token = getQueryParam(query, "token")
        val state = pendingTransfers[token]
        if (state == null) {
            sendResponse(output, 404, "Not Found", "application/json", "{\"status\":\"NOT_FOUND\"}")
            return
        }

        if (System.currentTimeMillis() > state.expiresAt) {
            pendingTransfers.remove(token)
            sendResponse(output, 200, "OK", "application/json", "{\"status\":\"EXPIRED\"}")
            return
        }

        val resp = """{"status":"${state.status}"}"""
        sendResponse(output, 200, "OK", "application/json", resp)
    }

    private fun handleFileUpload(input: InputStream, output: OutputStream, query: String, contentLength: Long) {
        val token = getQueryParam(query, "token")
        val filenameRaw = getQueryParam(query, "filename")
        val filename = try {
            URLDecoder.decode(filenameRaw, "UTF-8")
        } catch (_: Exception) {
            filenameRaw
        }

        val state = pendingTransfers[token]
        if (state == null || state.status != "ACCEPTED" || System.currentTimeMillis() > state.expiresAt) {
            sendResponse(output, 403, "Forbidden", "application/json", "{\"error\":\"Unauthorized or expired transfer\"}")
            return
        }

        val (saved, finalName) = StorageUtils.saveIncomingStream(
            context = context,
            filename = filename,
            inputStream = input,
            totalBytes = contentLength
        )

        if (saved) {
            pendingTransfers.remove(token)
            Handler(Looper.getMainLooper()).post {
                onFileReceived?.invoke(finalName, contentLength)
            }
            val resp = """{"status":"OK","filename":"$finalName","size":$contentLength}"""
            sendResponse(output, 200, "OK", "application/json", resp)
        } else {
            sendResponse(output, 500, "Internal Server Error", "application/json", "{\"error\":\"Failed to save file\"}")
        }
    }

    private fun handleClipboard(input: InputStream, output: OutputStream, contentLength: Long) {
        if (contentLength > 1024 * 1024) {
            sendResponse(output, 400, "Bad Request", "application/json", "{\"error\":\"Payload too large\"}")
            return
        }
        val bodyBytes = ByteArray(contentLength.toInt())
        var totalRead = 0
        while (totalRead < bodyBytes.size) {
            val r = input.read(bodyBytes, totalRead, bodyBytes.size - totalRead)
            if (r == -1) break
            totalRead += r
        }

        try {
            val bodyJson = String(bodyBytes, Charsets.UTF_8)
            val payload = json.decodeFromString<ClipboardPayload>(bodyJson)

            Handler(Looper.getMainLooper()).post {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                val clip = ClipData.newPlainText("OmaSend", payload.text)
                clipboard?.setPrimaryClip(clip)
                onClipboardReceived?.invoke(payload.sender_name, payload.text)
            }

            sendResponse(output, 200, "OK", "application/json", "{\"status\":\"OK\"}")
        } catch (_: Exception) {
            sendResponse(output, 400, "Bad Request", "application/json", "{\"error\":\"Invalid payload\"}")
        }
    }

    private fun getQueryParam(query: String, param: String): String {
        val pairs = query.split("&")
        for (pair in pairs) {
            val parts = pair.split("=")
            if (parts.size == 2 && parts[0] == param) {
                return parts[1]
            }
        }
        return ""
    }

    private fun sendResponse(
        output: OutputStream,
        code: Int,
        statusText: String,
        contentType: String,
        body: String
    ) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        val header = "HTTP/1.1 $code $statusText\r\n" +
                "Content-Type: $contentType\r\n" +
                "Content-Length: ${bytes.size}\r\n" +
                "Connection: close\r\n" +
                "\r\n"
        output.write(header.toByteArray(Charsets.UTF_8))
        output.write(bytes)
        output.flush()
    }
}
