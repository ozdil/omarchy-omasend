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
import java.util.concurrent.atomic.AtomicInteger

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

    companion object {
        const val MAX_GLOBAL_CONNECTIONS = 8
        const val MAX_PER_PEER_CONNECTIONS = 2
        const val MAX_HEADER_SIZE = 65536 // 64 KiB ceiling to prevent header DoS
        const val MAX_CONTROL_BODY = 65536 // 64 KiB ceiling for control JSON payloads
        const val MAX_CLIPBOARD_BODY = 1048576 // 1 MiB ceiling matching Omarchy standard
        const val HEADER_READ_TIMEOUT_MS = 15000L // 15s monotonic deadline for header read
        const val CONTROL_DEADLINE_MS = 30000L // 30s monotonic end-to-end deadline for control requests
        const val MAX_FAILED_AUTH_ATTEMPTS = 5
        const val FAILED_AUTH_WINDOW_MS = 60000L // 1 minute window
        const val AUTH_BLOCK_DURATION_MS = 60000L // 1 minute block
    }

    private data class FailedAttemptRecord(
        var count: Int,
        var firstAttemptTime: Long,
        var blockedUntil: Long
    )

    private val activeGlobalConnections = AtomicInteger(0)
    private val activePerPeerConnections = ConcurrentHashMap<String, AtomicInteger>()
    private val failedAuthAttempts = ConcurrentHashMap<String, FailedAttemptRecord>()
    private val trustedPeers = ConcurrentHashMap<String, Long>()

    fun addTrustedPeer(senderId: String) {
        if (senderId.isNotBlank()) {
            trustedPeers[senderId] = System.currentTimeMillis()
        }
    }

    fun isPeerTrusted(senderId: String): Boolean {
        if (senderId.isBlank()) return false
        return trustedPeers.containsKey(senderId)
    }

    fun acceptTransfer(token: String) {
        val state = pendingTransfers[token] ?: return
        state.status = "ACCEPTED"
        addTrustedPeer(state.prompt.senderId)
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
                    val clientSocket = try {
                        serverSocket?.accept() ?: break
                    } catch (_: Exception) {
                        break
                    }

                    // Strict RFC 1918 / 3927 private network scope check BEFORE launching work
                    val remoteAddr = clientSocket.inetAddress
                    if (remoteAddr == null || !NetworkUtils.isPrivateOrLocalAddress(remoteAddr)) {
                        try { clientSocket.close() } catch (_: Exception) {}
                        continue
                    }
                    val peerIp = remoteAddr.hostAddress ?: ""

                    // Strict Global Concurrency Limit BEFORE launching work
                    if (activeGlobalConnections.get() >= MAX_GLOBAL_CONNECTIONS) {
                        try { clientSocket.close() } catch (_: Exception) {}
                        continue
                    }

                    // Strict Per-Peer Concurrency Limit BEFORE launching work
                    val peerCounter = activePerPeerConnections.computeIfAbsent(peerIp) { AtomicInteger(0) }
                    if (peerCounter.get() >= MAX_PER_PEER_CONNECTIONS) {
                        try { clientSocket.close() } catch (_: Exception) {}
                        continue
                    }

                    // Acquire concurrency slots
                    activeGlobalConnections.incrementAndGet()
                    peerCounter.incrementAndGet()

                    scope.launch {
                        try {
                            handleClient(clientSocket, peerIp)
                        } finally {
                            activeGlobalConnections.decrementAndGet()
                            if (peerCounter.decrementAndGet() <= 0) {
                                activePerPeerConnections.remove(peerIp, peerCounter)
                            }
                        }
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

    var getDiscoveryMode: (() -> io.omarchy.omasend.model.DiscoveryMode)? = null

    private fun handleClient(socket: Socket, peerIp: String) {
        try {
            val monotonicStart = System.currentTimeMillis()
            val headerDeadline = monotonicStart + HEADER_READ_TIMEOUT_MS

            socket.soTimeout = 3000 // 3-second SO_TIMEOUT to periodically verify monotonic deadline
            val input = BufferedInputStream(socket.getInputStream())
            val output = socket.getOutputStream()

            // Read HTTP headers with strict byte ceiling and monotonic deadline
            val headerBytes = ByteArrayOutputStream()
            var prev1 = -1
            var prev2 = -1
            var prev3 = -1
            var curr: Int

            while (true) {
                if (System.currentTimeMillis() > headerDeadline) {
                    socket.close()
                    return
                }
                try {
                    curr = input.read()
                } catch (_: java.net.SocketTimeoutException) {
                    if (System.currentTimeMillis() > headerDeadline) {
                        socket.close()
                        return
                    }
                    continue
                }
                if (curr == -1) {
                    socket.close()
                    return
                }
                headerBytes.write(curr)
                if (headerBytes.size() > MAX_HEADER_SIZE) {
                    socket.close()
                    return
                }
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

            // Early Visibility Check: reject connections if visibility is turned OFF
            val currentMode = getDiscoveryMode?.invoke()
            if (currentMode == io.omarchy.omasend.model.DiscoveryMode.OFF && path != "/api/status") {
                sendResponse(output, 403, "Forbidden", "application/json", "{\"error\":\"Visibility is Off\"}")
                return
            }

            val remainingDeadline = monotonicStart + CONTROL_DEADLINE_MS

            when {
                path == "/api/status" || path == "/api/p2p/ping" -> {
                    handlePing(output)
                }
                method == "POST" && path == "/api/p2p/request" -> {
                    handleTransferRequest(input, output, contentLength, remainingDeadline)
                }
                method == "GET" && path == "/api/p2p/decision" -> {
                    handleDecisionQuery(output, query)
                }
                method == "POST" && path == "/api/p2p/upload" -> {
                    handleFileUpload(input, output, query, contentLength)
                }
                method == "POST" && path == "/api/p2p/clipboard" -> {
                    handleClipboard(input, output, headers, query, contentLength, peerIp, remainingDeadline)
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

    private fun handleTransferRequest(
        input: InputStream,
        output: OutputStream,
        contentLength: Long,
        deadlineMs: Long
    ) {
        if (contentLength <= 0 || contentLength > MAX_CONTROL_BODY) {
            sendResponse(output, 400, "Bad Request", "application/json", "{\"error\":\"Invalid or excessive payload\"}")
            return
        }
        val bodyBytes = ByteArray(contentLength.toInt())
        var totalRead = 0
        while (totalRead < bodyBytes.size) {
            if (System.currentTimeMillis() > deadlineMs) {
                sendResponse(output, 408, "Request Timeout", "application/json", "{\"error\":\"Request body timed out\"}")
                return
            }
            val r = try {
                input.read(bodyBytes, totalRead, bodyBytes.size - totalRead)
            } catch (_: java.net.SocketTimeoutException) {
                if (System.currentTimeMillis() > deadlineMs) {
                    sendResponse(output, 408, "Request Timeout", "application/json", "{\"error\":\"Request body timed out\"}")
                    return
                }
                continue
            }
            if (r == -1) break
            totalRead += r
        }

        if (totalRead < bodyBytes.size) {
            sendResponse(output, 400, "Bad Request", "application/json", "{\"error\":\"Incomplete payload\"}")
            return
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
        } catch (_: Exception) {
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

        if (contentLength <= 0 || contentLength > StorageUtils.MAX_FILE_SIZE) {
            sendResponse(output, 400, "Bad Request", "application/json", "{\"error\":\"Invalid or excessive file size\"}")
            return
        }

        val state = pendingTransfers[token]
        if (state == null || state.status != "ACCEPTED" || System.currentTimeMillis() > state.expiresAt) {
            sendResponse(output, 403, "Forbidden", "application/json", "{\"error\":\"Unauthorized or expired transfer\"}")
            return
        }

        val uploadDurationMs = ((contentLength / (512 * 1024L)).coerceIn(30L, 600L)) * 1000L
        val uploadDeadline = System.currentTimeMillis() + uploadDurationMs

        val (saved, finalName) = StorageUtils.saveIncomingStream(
            context = context,
            filename = filename,
            inputStream = input,
            totalBytes = contentLength,
            deadlineMs = uploadDeadline
        )

        if (saved) {
            pendingTransfers.remove(token)
            Handler(Looper.getMainLooper()).post {
                onFileReceived?.invoke(finalName, contentLength)
            }
            val resp = """{"status":"OK","filename":"$finalName","size":$contentLength}"""
            sendResponse(output, 200, "OK", "application/json", resp)
        } else {
            sendResponse(output, 500, "Internal Server Error", "application/json", "{\"error\":\"Failed to save file: $finalName\"}")
        }
    }

    private fun isAuthRateLimited(peerIp: String): Boolean {
        val now = System.currentTimeMillis()
        val rec = failedAuthAttempts[peerIp] ?: return false
        if (now < rec.blockedUntil) return true
        if (now - rec.firstAttemptTime > FAILED_AUTH_WINDOW_MS) {
            failedAuthAttempts.remove(peerIp)
            return false
        }
        return false
    }

    private fun recordAuthAttempt(peerIp: String, success: Boolean): Boolean {
        val now = System.currentTimeMillis()
        if (success) {
            failedAuthAttempts.remove(peerIp)
            return true
        }
        val rec = failedAuthAttempts.compute(peerIp) { _, existing ->
            if (existing == null || (now - existing.firstAttemptTime > FAILED_AUTH_WINDOW_MS && now >= existing.blockedUntil)) {
                FailedAttemptRecord(count = 1, firstAttemptTime = now, blockedUntil = 0L)
            } else {
                existing.count++
                if (existing.count >= MAX_FAILED_AUTH_ATTEMPTS) {
                    existing.blockedUntil = now + AUTH_BLOCK_DURATION_MS
                }
                existing
            }
        }
        return (rec?.blockedUntil ?: 0L) <= now
    }

    private fun handleClipboard(
        input: InputStream,
        output: OutputStream,
        headers: Map<String, String>,
        query: String,
        contentLength: Long,
        peerIp: String,
        deadlineMs: Long
    ) {
        // 1. Rate-limiting check: reject blocked IP immediately
        if (isAuthRateLimited(peerIp)) {
            sendResponse(
                output,
                429,
                "Too Many Requests",
                "application/json",
                "{\"error\":\"Too many failed authentication attempts. Please wait 60 seconds.\"}"
            )
            return
        }

        // 2. Monotonic body reading
        if (contentLength <= 0 || contentLength > MAX_CLIPBOARD_BODY) {
            sendResponse(output, 400, "Bad Request", "application/json", "{\"error\":\"Invalid or excessive payload\"}")
            return
        }

        val bodyBytes = ByteArray(contentLength.toInt())
        var totalRead = 0
        while (totalRead < bodyBytes.size) {
            if (System.currentTimeMillis() > deadlineMs) {
                sendResponse(output, 408, "Request Timeout", "application/json", "{\"error\":\"Clipboard read timed out\"}")
                return
            }
            val r = try {
                input.read(bodyBytes, totalRead, bodyBytes.size - totalRead)
            } catch (_: java.net.SocketTimeoutException) {
                if (System.currentTimeMillis() > deadlineMs) {
                    sendResponse(output, 408, "Request Timeout", "application/json", "{\"error\":\"Clipboard read timed out\"}")
                    return
                }
                continue
            }
            if (r == -1) break
            totalRead += r
        }

        if (totalRead < bodyBytes.size) {
            sendResponse(output, 400, "Bad Request", "application/json", "{\"error\":\"Incomplete payload\"}")
            return
        }

        val bodyJson = String(bodyBytes, Charsets.UTF_8)
        val payload = try {
            json.decodeFromString<ClipboardPayload>(bodyJson)
        } catch (_: Exception) {
            sendResponse(output, 400, "Bad Request", "application/json", "{\"error\":\"Invalid JSON payload\"}")
            return
        }

        // 3. Authenticate and Authorize
        val providedPin = headers["x-omasend-pin"]
            ?: getQueryParam(query, "pin").ifBlank { null }
            ?: payload.pin

        val providedKey = headers["x-omasend-key"]
            ?: headers["authorization"]?.removePrefix("Bearer ")?.trim()
            ?: getQueryParam(query, "token").ifBlank { null }
            ?: payload.token

        val expectedPin = NetworkUtils.getDevicePin(context)
        val expectedSessionKey = NetworkUtils.getDeviceSessionKey(context)

        val isPinValid = !providedPin.isNullOrBlank() && providedPin == expectedPin
        val isKeyValid = !providedKey.isNullOrBlank() && providedKey == expectedSessionKey

        val isTokenValid = !providedKey.isNullOrBlank() &&
            pendingTransfers[providedKey]?.status == "ACCEPTED" &&
            System.currentTimeMillis() <= (pendingTransfers[providedKey]?.expiresAt ?: 0L)

        val isTrustedPeer = !payload.sender_id.isBlank() && isPeerTrusted(payload.sender_id)

        val isAuthorized = isPinValid || isKeyValid || isTokenValid || isTrustedPeer

        if (!isAuthorized) {
            val notBlocked = recordAuthAttempt(peerIp, false)
            if (!notBlocked) {
                sendResponse(
                    output,
                    429,
                    "Too Many Requests",
                    "application/json",
                    "{\"error\":\"Too many failed authentication attempts. Please wait 60 seconds.\"}"
                )
            } else {
                sendResponse(
                    output,
                    401,
                    "Unauthorized",
                    "application/json",
                    "{\"error\":\"Unauthorized clipboard write: valid PIN, session key, or paired token required\"}"
                )
            }
            return
        }

        // Authorized: reset failed attempts
        recordAuthAttempt(peerIp, true)

        Handler(Looper.getMainLooper()).post {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            val clip = ClipData.newPlainText("OmaSend", payload.text)
            clipboard?.setPrimaryClip(clip)
            onClipboardReceived?.invoke(payload.sender_name, payload.text)
        }

        sendResponse(output, 200, "OK", "application/json", "{\"status\":\"OK\"}")
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
