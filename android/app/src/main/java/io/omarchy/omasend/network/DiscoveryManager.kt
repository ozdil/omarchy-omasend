package io.omarchy.omasend.network

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import io.omarchy.omasend.crypto.OmaIdentity
import io.omarchy.omasend.model.DiscoveryMode
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
import java.net.NetworkInterface
import java.util.concurrent.ConcurrentHashMap

class DiscoveryManager(private val context: Context) {
    private val scope = CoroutineScope(Dispatchers.IO)
    private var broadcastJob: Job? = null
    private var listenJob: Job? = null
    private var cleanupJob: Job? = null

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }
    private val prefs = context.getSharedPreferences("omasend_trusted_peers", Context.MODE_PRIVATE)
    private val pairedPrefs = context.getSharedPreferences("omasend_paired_peers", Context.MODE_PRIVATE)
    private val peerMap = ConcurrentHashMap<String, DiscoveredPeer>()
    private val _peers = MutableStateFlow<List<DiscoveredPeer>>(emptyList())
    val peers: StateFlow<List<DiscoveredPeer>> = _peers.asStateFlow()
    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()
    private val _discoveryMode = MutableStateFlow(DiscoveryMode.EVERYONE)
    val discoveryMode: StateFlow<DiscoveryMode> = _discoveryMode.asStateFlow()

    private var lastActiveEventTime: Long = System.currentTimeMillis()
    private val _currentDutyCycleMs = MutableStateFlow(ACTIVE_INTERVAL_MS)
    val currentDutyCycleMs: StateFlow<Long> = _currentDutyCycleMs.asStateFlow()

    companion object {
        const val ACTIVE_INTERVAL_MS = 1000L      // 1s active discovery when peers present or newly started
        const val SEARCH_INTERVAL_MS = 2000L      // 2s intermediate search when idle
        const val IDLE_INTERVAL_MS = 6000L        // 6s deep idle duty cycle (energy saving)
        const val SEARCH_THRESHOLD_MS = 10_000L   // 10s idle threshold -> 2s interval
        const val IDLE_THRESHOLD_MS = 30_000L     // 30s idle threshold -> 6s interval
        const val PEER_EXPIRY_TIMEOUT_MS = 18_000L // 3 missed beacons @ 6s duty cycle
        private const val KEY_PAIRED_OMA_IDS = "paired_oma_ids"

        fun calculateAdaptiveInterval(
            lastActiveEventTime: Long,
            hasActivePeers: Boolean,
            currentTimeMs: Long = System.currentTimeMillis()
        ): Long {
            if (hasActivePeers) {
                return ACTIVE_INTERVAL_MS
            }
            val idleDuration = currentTimeMs - lastActiveEventTime
            return when {
                idleDuration < SEARCH_THRESHOLD_MS -> ACTIVE_INTERVAL_MS
                idleDuration < IDLE_THRESHOLD_MS -> SEARCH_INTERVAL_MS
                else -> IDLE_INTERVAL_MS
            }
        }
    }

    fun markActiveEvent(currentTimeMs: Long = System.currentTimeMillis()) {
        lastActiveEventTime = currentTimeMs
        _currentDutyCycleMs.value = ACTIVE_INTERVAL_MS
    }

    fun calculateAdaptiveInterval(currentTimeMs: Long = System.currentTimeMillis()): Long {
        val now = currentTimeMs
        val hasActivePeers = peerMap.values.any { !it.id.startsWith("manual_") && (now - it.lastSeen <= PEER_EXPIRY_TIMEOUT_MS) }
        if (hasActivePeers) {
            lastActiveEventTime = now
        }
        val interval = calculateAdaptiveInterval(lastActiveEventTime, hasActivePeers, now)
        _currentDutyCycleMs.value = interval
        return interval
    }

    // ------------------- OMAID PAIRING STORE -------------------

    fun getPairedOmaIds(): Set<String> {
        return pairedPrefs.getStringSet(KEY_PAIRED_OMA_IDS, emptySet()) ?: emptySet()
    }

    fun isOmaIdPaired(omaId: String): Boolean {
        if (omaId.isBlank()) return false
        val clean = OmaIdentity.unformat(omaId)
        val paired = getPairedOmaIds()
        return paired.any { OmaIdentity.unformat(it) == clean }
    }

    fun addPairedOmaId(omaId: String) {
        if (!OmaIdentity.isValid(omaId)) return
        val formatted = OmaIdentity.format(omaId)
        val current = getPairedOmaIds().toMutableSet()
        current.add(formatted)
        pairedPrefs.edit().putStringSet(KEY_PAIRED_OMA_IDS, current).apply()

        // Update all discovered peers matching this OmaID
        val clean = OmaIdentity.unformat(omaId)
        for ((id, peer) in peerMap) {
            if (OmaIdentity.unformat(peer.omaId) == clean || OmaIdentity.unformat(peer.fingerprint) == clean) {
                peerMap[id] = peer.copy(isTrusted = true, omaId = formatted)
            }
        }
        updatePeersFlow()
    }

    fun removePairedOmaId(omaId: String) {
        val formatted = OmaIdentity.format(omaId)
        val current = getPairedOmaIds().toMutableSet()
        current.remove(formatted)
        pairedPrefs.edit().putStringSet(KEY_PAIRED_OMA_IDS, current).apply()
        updatePeersFlow()
    }

    fun isPeerTrusted(peerId: String): Boolean {
        return prefs.getBoolean("trusted_$peerId", false)
    }

    fun setPeerTrusted(peerId: String, trusted: Boolean) {
        prefs.edit().putBoolean("trusted_$peerId", trusted).apply()
        peerMap[peerId]?.let { peer ->
            peerMap[peerId] = peer.copy(isTrusted = trusted)
        }
        updatePeersFlow()
    }

    fun toggleTrust(peerId: String) {
        val current = isPeerTrusted(peerId)
        setPeerTrusted(peerId, !current)
    }

    private fun updatePeersFlow() {
        val mode = _discoveryMode.value
        val list = when (mode) {
            DiscoveryMode.OFF -> emptyList()
            DiscoveryMode.KNOWN_PEERS -> {
                peerMap.values.filter { it.isTrusted || isOmaIdPaired(it.omaId) || it.id.startsWith("manual_") || it.transport == "DIRECT" }
            }
            DiscoveryMode.EVERYONE -> {
                peerMap.values.toList()
            }
        }
        _peers.value = list.sortedBy { it.name }
    }

    private fun sendBroadcastPacket(socket: DatagramSocket, payload: ByteArray, port: Int) {
        // 1. Global Broadcast
        try {
            val bcastAddr = InetAddress.getByName("255.255.255.255")
            socket.send(DatagramPacket(payload, payload.size, bcastAddr, port))
        } catch (_: Exception) {}

        // 2. Subnet Broadcast on all active network interfaces
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val netIf = interfaces.nextElement()
                if (!netIf.isUp || netIf.isLoopback) continue
                for (addr in netIf.interfaceAddresses) {
                    val bcast = addr.broadcast
                    if (bcast != null) {
                        try {
                            socket.send(DatagramPacket(payload, payload.size, bcast, port))
                        } catch (_: Exception) {}
                    }
                }
            }
        } catch (_: Exception) {}
    }

    private fun getMyOmaId(): String {
        return try {
            val app = context.applicationContext as? io.omarchy.omasend.OmaSendApp
            app?.omaIdentity?.formattedId ?: OmaIdentity.getOrGenerate(context).formattedId
        } catch (_: Exception) {
            ""
        }
    }

    fun forceRefresh() {
        markActiveEvent()
        scope.launch {
            val myIp = NetworkUtils.getLocalIpAddress()
            if (myIp != "127.0.0.1") {
                try {
                    val socket = DatagramSocket().apply { broadcast = true }
                    val myOmaId = getMyOmaId()
                    val beacon = P2pBeaconPacket(
                        magic = "OMASEND_P2P",
                        v = 1,
                        id = NetworkUtils.getDeviceId(context),
                        name = NetworkUtils.getDeviceName(context),
                        ip = myIp,
                        port = NetworkUtils.PORT,
                        mode = _discoveryMode.value.wireMode,
                        oma_id = myOmaId,
                        fp = myOmaId
                    )
                    val payload = json.encodeToString(P2pBeaconPacket.serializer(), beacon).toByteArray(Charsets.UTF_8)
                    repeat(3) {
                        sendBroadcastPacket(socket, payload, NetworkUtils.PORT)
                        for (peer in peerMap.values) {
                            try {
                                val peerAddr = InetAddress.getByName(peer.ip)
                                socket.send(DatagramPacket(payload, payload.size, peerAddr, peer.port))
                            } catch (_: Exception) {}
                        }
                        delay(60)
                    }
                    socket.close()
                } catch (_: Exception) {
                }
            }
            updatePeersFlow()
        }
    }

    fun setMode(mode: DiscoveryMode) {
        _discoveryMode.value = mode
        when (mode) {
            DiscoveryMode.OFF -> stop()
            DiscoveryMode.KNOWN_PEERS -> {
                if (!_isScanning.value) start()
                else updatePeersFlow()
            }
            DiscoveryMode.EVERYONE -> {
                if (!_isScanning.value) start()
                else updatePeersFlow()
            }
        }
    }

    private var multicastLock: WifiManager.MulticastLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    private fun acquireLocks() {
        try {
            val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            if (wifi != null) {
                if (multicastLock == null) {
                    multicastLock = wifi.createMulticastLock("OmaSendMulticastLock").apply {
                        setReferenceCounted(false)
                    }
                }
                if (multicastLock?.isHeld == false) {
                    multicastLock?.acquire()
                }

                if (wifiLock == null) {
                    val lockMode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                    } else {
                        @Suppress("DEPRECATION")
                        WifiManager.WIFI_MODE_FULL_HIGH_PERF
                    }
                    wifiLock = wifi.createWifiLock(lockMode, "OmaSendWifiLock").apply {
                        setReferenceCounted(false)
                    }
                }
                if (wifiLock?.isHeld == false) {
                    wifiLock?.acquire()
                }
            }
        } catch (_: Exception) {}
    }

    private fun releaseLocks() {
        try {
            if (multicastLock?.isHeld == true) {
                multicastLock?.release()
            }
            if (wifiLock?.isHeld == true) {
                wifiLock?.release()
            }
        } catch (_: Exception) {}
    }

    private fun broadcastOfflineBeacon() {
        scope.launch {
            val myIp = NetworkUtils.getLocalIpAddress()
            if (myIp != "127.0.0.1") {
                try {
                    val socket = DatagramSocket().apply { broadcast = true }
                    val myOmaId = getMyOmaId()
                    val beacon = P2pBeaconPacket(
                        magic = "OMASEND_P2P",
                        v = 1,
                        id = NetworkUtils.getDeviceId(context),
                        name = NetworkUtils.getDeviceName(context),
                        ip = myIp,
                        port = NetworkUtils.PORT,
                        mode = "OFF",
                        oma_id = myOmaId,
                        fp = myOmaId
                    )
                    val payload = json.encodeToString(P2pBeaconPacket.serializer(), beacon).toByteArray(Charsets.UTF_8)
                    repeat(2) {
                        sendBroadcastPacket(socket, payload, NetworkUtils.PORT)
                        for (peer in peerMap.values) {
                            try {
                                val peerAddr = InetAddress.getByName(peer.ip)
                                socket.send(DatagramPacket(payload, payload.size, peerAddr, peer.port))
                            } catch (_: Exception) {}
                        }
                        delay(50)
                    }
                    socket.close()
                } catch (_: Exception) {}
            }
        }
    }

    fun start() {
        if (_isScanning.value) return
        _isScanning.value = true
        markActiveEvent()
        if (_discoveryMode.value == DiscoveryMode.OFF) {
            _discoveryMode.value = DiscoveryMode.EVERYONE
        }
        acquireLocks()
        startListener()
        startBroadcaster()
        startCleanup()
        updatePeersFlow()
    }

    fun stop() {
        _isScanning.value = false
        _discoveryMode.value = DiscoveryMode.OFF
        broadcastOfflineBeacon()
        broadcastJob?.cancel()
        listenJob?.cancel()
        cleanupJob?.cancel()
        broadcastJob = null
        listenJob = null
        cleanupJob = null
        releaseLocks()
        // Retain manual peers if any, but clear discovered peers so UI reflects paused state
        val manualPeers = peerMap.values.filter { it.id.startsWith("manual_") }
        peerMap.clear()
        manualPeers.forEach { peerMap[it.id] = it }
        updatePeersFlow()
    }

    fun addManualPeer(ip: String, port: Int = NetworkUtils.PORT, name: String = "Direct ($ip)") {
        if (!NetworkUtils.isPrivateOrLocalIp(ip)) return
        val peer = DiscoveredPeer(
            id = "manual_${ip.replace('.', '_')}_$port",
            name = name,
            ip = ip,
            port = port,
            transport = "DIRECT",
            omaId = "",
            fingerprint = "",
            isTrusted = true,
            lastSeen = System.currentTimeMillis() + 3600000L // 1 hour persistent
        )
        peerMap[peer.id] = peer
        updatePeersFlow()
    }

    fun addRendezvousPeer(peer: DiscoveredPeer) {
        peerMap[peer.id] = peer
        updatePeersFlow()
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
                        val packetAddr = packet.address
                        if (packetAddr == null || !NetworkUtils.isPrivateOrLocalAddress(packetAddr)) continue

                        val length = packet.length
                        if (length > 0) {
                            val rawJson = String(packet.data, 0, length, Charsets.UTF_8)
                            val beacon = json.decodeFromString<P2pBeaconPacket>(rawJson)
                            if (beacon.magic == "OMASEND_P2P") {
                                val myId = NetworkUtils.getDeviceId(context)
                                val myIp = NetworkUtils.getLocalIpAddress()
                                if (beacon.id != myId && beacon.ip != myIp) {
                                    // Remote peer notified OFFLINE
                                    if (beacon.mode.equals("OFF", ignoreCase = true) || beacon.mode.equals("STOP", ignoreCase = true)) {
                                        val removed = peerMap.remove(beacon.id) != null
                                        if (removed) {
                                            updatePeersFlow()
                                        }
                                        continue
                                    }

                                    val senderIp = packetAddr.hostAddress ?: beacon.ip
                                    val peerOmaId = if (beacon.oma_id.isNotBlank()) beacon.oma_id else beacon.fp
                                    val isPaired = isOmaIdPaired(peerOmaId) || isPeerTrusted(beacon.id)

                                    val peer = DiscoveredPeer(
                                        id = beacon.id,
                                        name = beacon.name,
                                        ip = senderIp,
                                        port = beacon.port,
                                        transport = "LAN",
                                        omaId = peerOmaId,
                                        fingerprint = peerOmaId,
                                        isTrusted = isPaired,
                                        lastSeen = System.currentTimeMillis()
                                    )
                                    peerMap[peer.id] = peer
                                    markActiveEvent()
                                    updatePeersFlow()
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
                        val myOmaId = getMyOmaId()
                        val beacon = P2pBeaconPacket(
                            magic = "OMASEND_P2P",
                            v = 1,
                            id = NetworkUtils.getDeviceId(context),
                            name = NetworkUtils.getDeviceName(context),
                            ip = myIp,
                            port = NetworkUtils.PORT,
                            mode = _discoveryMode.value.wireMode,
                            oma_id = myOmaId,
                            fp = myOmaId
                        )
                        val payload = json.encodeToString(P2pBeaconPacket.serializer(), beacon).toByteArray(Charsets.UTF_8)

                        // Broadcaster handles global and active subnet interfaces
                        sendBroadcastPacket(socket, payload, NetworkUtils.PORT)

                        // Direct Unicast to discovered peers (bypasses Wi-Fi broadcast drops)
                        for (peer in peerMap.values) {
                            try {
                                val peerAddr = InetAddress.getByName(peer.ip)
                                socket.send(DatagramPacket(payload, payload.size, peerAddr, peer.port))
                            } catch (_: Exception) {
                            }
                        }
                    }
                    val interval = calculateAdaptiveInterval()
                    delay(interval)
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
                delay(3000)
                val now = System.currentTimeMillis()
                var changed = false
                val it = peerMap.entries.iterator()
                while (it.hasNext()) {
                    val entry = it.next()
                    if (!entry.value.id.startsWith("manual_") && (now - entry.value.lastSeen > PEER_EXPIRY_TIMEOUT_MS)) {
                        it.remove()
                        changed = true
                    }
                }
                if (changed) {
                    updatePeersFlow()
                }
            }
        }
    }
}
