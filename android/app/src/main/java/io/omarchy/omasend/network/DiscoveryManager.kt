package io.omarchy.omasend.network

import android.content.Context
import android.net.wifi.WifiManager
import io.omarchy.omasend.model.DiscoveredPeer
import io.omarchy.omasend.model.P2pBeaconPacket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

class DiscoveryManager(private val context: Context) {
    private val scope = CoroutineScope(Dispatchers.IO)
    private var broadcastJob: Job? = null
    private var listenJob: Job? = null
    private var cleanupJob: Job? = null
    private var multicastLock: WifiManager.MulticastLock? = null

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }
    private val peerMap = ConcurrentHashMap<String, DiscoveredPeer>()
    private val _peers = MutableStateFlow<List<DiscoveredPeer>>(emptyList())
    val peers: StateFlow<List<DiscoveredPeer>> = _peers.asStateFlow()

    fun start() {
        acquireMulticastLock()
        startListener()
        startBroadcaster()
        startCleanup()
    }

    fun stop() {
        broadcastJob?.cancel()
        listenJob?.cancel()
        cleanupJob?.cancel()
        releaseMulticastLock()
    }

    fun addManualPeer(ip: String, port: Int = NetworkUtils.PORT, name: String = "Direct ($ip)") {
        val peer = DiscoveredPeer(
            id = "manual_${ip.replace('.', '_')}_$port",
            name = name,
            ip = ip,
            port = port,
            transport = "DIRECT",
            fingerprint = "",
            lastSeen = System.currentTimeMillis() + 3600000L // 1 hour persistent
        )
        peerMap[peer.id] = peer
        _peers.value = peerMap.values.toList().sortedBy { it.name }
    }

    private fun acquireMulticastLock() {
        try {
            val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            multicastLock = wifi?.createMulticastLock("OmaSendDiscoveryLock")?.apply {
                setReferenceCounted(true)
                acquire()
            }
        } catch (_: Exception) {
        }
    }

    private fun releaseMulticastLock() {
        try {
            if (multicastLock?.isHeld == true) {
                multicastLock?.release()
            }
        } catch (_: Exception) {
        }
    }

    private fun startListener() {
        listenJob?.cancel()
        listenJob = scope.launch {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket(NetworkUtils.PORT).apply {
                    broadcast = true
                    reuseAddress = true
                }
                val buffer = ByteArray(2048)
                val packet = DatagramPacket(buffer, buffer.size)

                while (isActive) {
                    try {
                        socket.receive(packet)
                        val length = packet.length
                        if (length > 0) {
                            val rawJson = String(packet.data, 0, length, Charsets.UTF_8)
                            val beacon = json.decodeFromString<P2pBeaconPacket>(rawJson)
                            if (beacon.magic == "OMASEND_P2P") {
                                val myId = NetworkUtils.getDeviceId(context)
                                val myIp = NetworkUtils.getLocalIpAddress()
                                if (beacon.id != myId && beacon.ip != myIp) {
                                    val senderIp = packet.address.hostAddress ?: beacon.ip
                                    val peer = DiscoveredPeer(
                                        id = beacon.id,
                                        name = beacon.name,
                                        ip = senderIp,
                                        port = beacon.port,
                                        transport = if (beacon.bt) "BT+LAN" else "LAN",
                                        fingerprint = beacon.fp,
                                        lastSeen = System.currentTimeMillis()
                                    )
                                    peerMap[peer.id] = peer
                                    _peers.value = peerMap.values.toList().sortedBy { it.name }
                                }
                            }
                        }
                    } catch (_: Exception) {
                    }
                }
            } catch (_: Exception) {
            } finally {
                socket?.close()
            }
        }
    }

    private fun startBroadcaster() {
        broadcastJob?.cancel()
        broadcastJob = scope.launch {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket().apply {
                    broadcast = true
                }

                while (isActive) {
                    val myIp = NetworkUtils.getLocalIpAddress()
                    if (myIp != "127.0.0.1") {
                        val beacon = P2pBeaconPacket(
                            magic = "OMASEND_P2P",
                            v = 1,
                            id = NetworkUtils.getDeviceId(context),
                            name = NetworkUtils.getDeviceName(context),
                            ip = myIp,
                            port = NetworkUtils.PORT,
                            mode = "ALL",
                            bt = false,
                            fp = ""
                        )
                        val payload = json.encodeToString(P2pBeaconPacket.serializer(), beacon).toByteArray(Charsets.UTF_8)

                        // 1. Global Broadcast
                        try {
                            val bcastAddr = InetAddress.getByName("255.255.255.255")
                            socket.send(DatagramPacket(payload, payload.size, bcastAddr, NetworkUtils.PORT))
                        } catch (_: Exception) {
                        }

                        // 2. Subnet Broadcast
                        val lastDot = myIp.lastIndexOf('.')
                        if (lastDot != -1) {
                            try {
                                val subnetBcast = InetAddress.getByName(myIp.substring(0, lastDot) + ".255")
                                socket.send(DatagramPacket(payload, payload.size, subnetBcast, NetworkUtils.PORT))
                            } catch (_: Exception) {
                            }
                        }

                        // 3. Direct Unicast to discovered peers (bypasses Wi-Fi broadcast drops)
                        for (peer in peerMap.values) {
                            try {
                                val peerAddr = InetAddress.getByName(peer.ip)
                                socket.send(DatagramPacket(payload, payload.size, peerAddr, peer.port))
                            } catch (_: Exception) {
                            }
                        }
                    }
                    delay(3000)
                }
            } catch (_: Exception) {
            } finally {
                socket?.close()
            }
        }
    }

    private fun startCleanup() {
        cleanupJob?.cancel()
        cleanupJob = scope.launch {
            while (isActive) {
                delay(5000)
                val now = System.currentTimeMillis()
                var changed = false
                val it = peerMap.entries.iterator()
                while (it.hasNext()) {
                    val entry = it.next()
                    if (now - entry.value.lastSeen > 15000) {
                        it.remove()
                        changed = true
                    }
                }
                if (changed) {
                    _peers.value = peerMap.values.toList().sortedBy { it.name }
                }
            }
        }
    }
}
