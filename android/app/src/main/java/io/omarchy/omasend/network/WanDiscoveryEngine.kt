package io.omarchy.omasend.network

import android.content.Context
import io.omarchy.omasend.crypto.OmaIdentity
import io.omarchy.omasend.model.DiscoveredPeer
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

@Serializable
data class WanEndpoint(
    val publicIp: String,
    val publicPort: Int
)

@Serializable
data class RendezvousPayload(
    val deviceId: String,
    val deviceName: String,
    val wanIp: String,
    val wanPort: Int,
    val localIp: String,
    val localPort: Int,
    val timestamp: Long = System.currentTimeMillis(),
    val omaId: String = ""
)

@Serializable
data class RendezvousBeacon(
    val blindTopic: String,
    val encryptedPayload: String,
    val timestamp: Long = System.currentTimeMillis(),
    val ttlSeconds: Long = 300L
)

enum class NetworkTransportMode {
    LAN,
    WAN,
    P2P_MESH
}

data class WanStatus(
    val publicIp: String? = null,
    val publicPort: Int = 0,
    val isWanReachable: Boolean = false,
    val blindTopic: String = "",
    val mode: NetworkTransportMode = NetworkTransportMode.LAN,
    val rendezvousPeers: List<DiscoveredPeer> = emptyList()
)

class WanDiscoveryEngine(
    private val context: Context? = null,
    private val identityProvider: () -> OmaIdentity = {
        context?.let { OmaIdentity.getOrGenerate(it) } ?: OmaIdentity(OmaIdentity.generateRandomOmaId())
    }
) {
    private val scope = CoroutineScope(Dispatchers.IO)
    private var engineJob: Job? = null
    private val remotePeers = ConcurrentHashMap<String, DiscoveredPeer>()

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    private val _status = MutableStateFlow(
        WanStatus(
            blindTopic = identityProvider().blindTopic,
            mode = NetworkTransportMode.LAN
        )
    )
    val status: StateFlow<WanStatus> = _status.asStateFlow()

    fun start() {
        if (engineJob?.isActive == true) return
        engineJob = scope.launch {
            while (isActive) {
                try {
                    refreshWanEndpoint()
                } catch (_: Exception) {}
                delay(30000L) // Refresh every 30s
            }
        }
    }

    fun stop() {
        engineJob?.cancel()
        engineJob = null
        remotePeers.clear()
        _status.value = _status.value.copy(
            isWanReachable = false,
            rendezvousPeers = emptyList()
        )
    }

    fun setNetworkMode(mode: NetworkTransportMode) {
        _status.value = _status.value.copy(mode = mode)
    }

    suspend fun refreshWanEndpoint(): WanEndpoint? = withContext(Dispatchers.IO) {
        val stunServers = listOf(
            Pair("stun.l.google.com", 19302),
            Pair("stun1.l.google.com", 19302),
            Pair("stun.cloudflare.com", 3478)
        )

        for ((host, port) in stunServers) {
            try {
                val endpoint = queryStunServer(host, port, 2500)
                if (endpoint != null && !NetworkUtils.isPrivateOrLocalIp(endpoint.publicIp)) {
                    val currentIdentity = identityProvider()
                    _status.value = _status.value.copy(
                        publicIp = endpoint.publicIp,
                        publicPort = endpoint.publicPort,
                        isWanReachable = true,
                        blindTopic = currentIdentity.blindTopic
                    )
                    return@withContext endpoint
                }
            } catch (_: Exception) {
                continue
            }
        }
        null
    }

    /**
     * Builds and sends RFC 5389 STUN Binding Request over UDP to discover external WAN IP and port.
     */
    fun queryStunServer(host: String, port: Int, timeoutMs: Int = 2500): WanEndpoint? {
        val socket = DatagramSocket()
        socket.soTimeout = timeoutMs
        try {
            val address = InetAddress.getByName(host)
            val transactionId = ByteArray(12)
            SecureRandom().nextBytes(transactionId)

            val request = buildStunBindingRequest(transactionId)
            val packet = DatagramPacket(request, request.size, address, port)
            socket.send(packet)

            val buffer = ByteArray(1024)
            val responsePacket = DatagramPacket(buffer, buffer.size)
            socket.receive(responsePacket)

            return parseStunBindingResponse(buffer, responsePacket.length, transactionId)
        } finally {
            socket.close()
        }
    }

    /**
     * Creates a 20-byte RFC 5389 STUN Binding Request.
     */
    fun buildStunBindingRequest(transactionId: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
        buffer.putShort(0x0001.toShort()) // STUN Binding Request
        buffer.putShort(0x0000.toShort()) // Message Length: 0
        buffer.putInt(0x2112A442)         // Magic Cookie
        buffer.put(transactionId)         // 12-byte Transaction ID
        return buffer.array()
    }

    /**
     * Parses RFC 5389 STUN Binding Response and extracts public IP and port from XOR-MAPPED-ADDRESS or MAPPED-ADDRESS.
     */
    fun parseStunBindingResponse(data: ByteArray, length: Int, expectedTransactionId: ByteArray): WanEndpoint? {
        if (length < 20) return null
        val buffer = ByteBuffer.wrap(data, 0, length).order(ByteOrder.BIG_ENDIAN)

        val msgType = buffer.short.toInt() and 0xFFFF
        // 0x0101 = Binding Success Response, 0x0111 = Binding Response
        if (msgType != 0x0101 && msgType != 0x0111) return null

        val msgLength = buffer.short.toInt() and 0xFFFF
        val magicCookie = buffer.int
        if (magicCookie != 0x2112A442) return null

        val txId = ByteArray(12)
        buffer.get(txId)
        if (!txId.contentEquals(expectedTransactionId)) return null

        var offset = 20
        while (offset + 4 <= length) {
            val attrType = buffer.short.toInt() and 0xFFFF
            val attrLength = buffer.short.toInt() and 0xFFFF
            offset += 4

            if (offset + attrLength > length) break

            if (attrType == 0x0020) { // XOR-MAPPED-ADDRESS
                if (attrLength >= 8) {
                    buffer.get() // Reserved
                    val family = buffer.get().toInt() and 0xFF
                    val xorPort = buffer.short.toInt() and 0xFFFF
                    val port = xorPort xor 0x2112

                    if (family == 0x01) { // IPv4
                        val xorIp = buffer.int
                        val ipInt = xorIp xor 0x2112A442
                        val ip = String.format(
                            "%d.%d.%d.%d",
                            (ipInt ushr 24) and 0xFF,
                            (ipInt ushr 16) and 0xFF,
                            (ipInt ushr 8) and 0xFF,
                            ipInt and 0xFF
                        )
                        return WanEndpoint(publicIp = ip, publicPort = port)
                    }
                }
            } else if (attrType == 0x0001) { // MAPPED-ADDRESS
                if (attrLength >= 8) {
                    buffer.get() // Reserved
                    val family = buffer.get().toInt() and 0xFF
                    val port = buffer.short.toInt() and 0xFFFF

                    if (family == 0x01) { // IPv4
                        val ipInt = buffer.int
                        val ip = String.format(
                            "%d.%d.%d.%d",
                            (ipInt ushr 24) and 0xFF,
                            (ipInt ushr 16) and 0xFF,
                            (ipInt ushr 8) and 0xFF,
                            ipInt and 0xFF
                        )
                        return WanEndpoint(publicIp = ip, publicPort = port)
                    }
                }
            } else {
                buffer.position(buffer.position() + attrLength)
            }

            // Attribute padding to 4-byte boundary
            val padding = (4 - (attrLength % 4)) % 4
            if (padding > 0 && offset + attrLength + padding <= length) {
                buffer.position(buffer.position() + padding)
                offset += padding
            }
            offset += attrLength
        }
        return null
    }

    /**
     * Creates an encrypted RendezvousBeacon ready for GitHub Discovery Anchor announcement.
     */
    fun createAnnouncementBeacon(
        endpoint: WanEndpoint,
        identity: OmaIdentity,
        deviceName: String,
        deviceId: String
    ): RendezvousBeacon {
        val payload = RendezvousPayload(
            deviceId = deviceId,
            deviceName = deviceName,
            wanIp = endpoint.publicIp,
            wanPort = endpoint.publicPort,
            localIp = NetworkUtils.getLocalIpAddress(),
            localPort = NetworkUtils.PORT,
            timestamp = System.currentTimeMillis(),
            omaId = identity.formattedId
        )
        val jsonPayload = json.encodeToString(RendezvousPayload.serializer(), payload)
        val encrypted = OmaIdentity.encryptString(jsonPayload, identity.formattedId)

        return RendezvousBeacon(
            blindTopic = identity.blindTopic,
            encryptedPayload = encrypted,
            timestamp = System.currentTimeMillis(),
            ttlSeconds = 300L
        )
    }

    /**
     * Decrypts a RendezvousBeacon using target OmaID.
     */
    fun decryptBeacon(beacon: RendezvousBeacon, omaId: String): RendezvousPayload? {
        val expectedTopic = OmaIdentity.deriveBlindTopic(omaId)
        if (!beacon.blindTopic.equals(expectedTopic, ignoreCase = true)) {
            return null
        }
        return try {
            val decryptedJson = OmaIdentity.decryptString(beacon.encryptedPayload, omaId)
            json.decodeFromString<RendezvousPayload>(decryptedJson)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Resolves a peer from a decrypted RendezvousPayload.
     */
    fun registerRendezvousPeer(payload: RendezvousPayload): DiscoveredPeer {
        val peer = DiscoveredPeer(
            id = "wan_${payload.deviceId}",
            name = payload.deviceName,
            ip = payload.wanIp,
            port = payload.wanPort,
            transport = "WAN",
            fingerprint = payload.omaId,
            isTrusted = true,
            lastSeen = payload.timestamp
        )
        remotePeers[peer.id] = peer
        _status.value = _status.value.copy(
            rendezvousPeers = remotePeers.values.toList()
        )
        return peer
    }
}
