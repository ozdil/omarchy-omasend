package io.omarchy.omasend.network

import android.content.Context
import android.net.wifi.WifiManager
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothClass
import android.os.Build
import android.Manifest
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
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
    private var multicastLock: WifiManager.MulticastLock? = null

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }
    private val prefs = context.getSharedPreferences("omasend_trusted_peers", Context.MODE_PRIVATE)
    private val peerMap = ConcurrentHashMap<String, DiscoveredPeer>()
    private val _peers = MutableStateFlow<List<DiscoveredPeer>>(emptyList())
    val peers: StateFlow<List<DiscoveredPeer>> = _peers.asStateFlow()
    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()
    private val _discoveryMode = MutableStateFlow(DiscoveryMode.EVERYONE)
    val discoveryMode: StateFlow<DiscoveryMode> = _discoveryMode.asStateFlow()

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
                peerMap.values.filter { it.isTrusted || it.id.startsWith("manual_") }
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

    fun forceRefresh() {
        scope.launch {
            val myIp = NetworkUtils.getLocalIpAddress()
            if (myIp != "127.0.0.1") {
                try {
                    val socket = DatagramSocket().apply { broadcast = true }
                    val beacon = P2pBeaconPacket(
                        magic = "OMASEND_P2P",
                        v = 1,
                        id = NetworkUtils.getDeviceId(context),
                        name = NetworkUtils.getDeviceName(context),
                        ip = myIp,
                        port = NetworkUtils.PORT,
                        mode = _discoveryMode.value.wireMode,
                        bt = isBluetoothEnabled(),
                        fp = ""
                    )
                    val payload = json.encodeToString(P2pBeaconPacket.serializer(), beacon).toByteArray(Charsets.UTF_8)
                    repeat(2) {
                        sendBroadcastPacket(socket, payload, NetworkUtils.PORT)
                        delay(100)
                    }
                    socket.close()
                } catch (_: Exception) {
                }
            }
            refreshBluetoothPeers()
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

    fun start() {
        if (_isScanning.value) return
        _isScanning.value = true
        if (_discoveryMode.value == DiscoveryMode.OFF) {
            _discoveryMode.value = DiscoveryMode.EVERYONE
        }
        acquireMulticastLock()
        refreshBluetoothPeers()
        startListener()
        startBroadcaster()
        startCleanup()
        updatePeersFlow()
    }

    fun stop() {
        _isScanning.value = false
        _discoveryMode.value = DiscoveryMode.OFF
        broadcastJob?.cancel()
        listenJob?.cancel()
        cleanupJob?.cancel()
        broadcastJob = null
        listenJob = null
        cleanupJob = null
        releaseMulticastLock()
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
            fingerprint = "",
            isTrusted = true,
            lastSeen = System.currentTimeMillis() + 3600000L // 1 hour persistent
        )
        peerMap[peer.id] = peer
        updatePeersFlow()
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
                                    val senderIp = packetAddr.hostAddress ?: beacon.ip
                                    // Deduplication: Look for existing Bluetooth peer with matching name or fingerprint
                                    val existingBtPeer = peerMap.values.find {
                                        it.id.startsWith("bt_") && (it.name.equals(beacon.name, ignoreCase = true) ||
                                            (it.fingerprint.isNotEmpty() && it.fingerprint.equals(beacon.fp, ignoreCase = true)))
                                    }
                                    if (existingBtPeer != null) {
                                        peerMap.remove(existingBtPeer.id)
                                    }

                                    val resolvedBtMac = if (existingBtPeer != null && existingBtPeer.fingerprint.isNotEmpty()) {
                                        existingBtPeer.fingerprint
                                    } else {
                                        beacon.fp
                                    }

                                    val isHybrid = existingBtPeer != null || beacon.bt
                                    val peer = DiscoveredPeer(
                                        id = beacon.id,
                                        name = beacon.name,
                                        ip = senderIp,
                                        port = beacon.port,
                                        transport = if (isHybrid) "HYBRID" else "LAN",
                                        fingerprint = resolvedBtMac,
                                        isTrusted = isPeerTrusted(beacon.id) || (existingBtPeer?.let { isPeerTrusted(it.id) } ?: false),
                                        lastSeen = System.currentTimeMillis()
                                    )
                                    peerMap[peer.id] = peer
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
                        val beacon = P2pBeaconPacket(
                            magic = "OMASEND_P2P",
                            v = 1,
                            id = NetworkUtils.getDeviceId(context),
                            name = NetworkUtils.getDeviceName(context),
                            ip = myIp,
                            port = NetworkUtils.PORT,
                            mode = _discoveryMode.value.wireMode,
                            bt = isBluetoothEnabled(),
                            fp = ""
                        )
                        val payload = json.encodeToString(P2pBeaconPacket.serializer(), beacon).toByteArray(Charsets.UTF_8)

                        // Broadcaster handles global and active subnet interfaces
                        sendBroadcastPacket(socket, payload, NetworkUtils.PORT)

                        // 3. Direct Unicast to discovered peers (bypasses Wi-Fi broadcast drops)
                        for (peer in peerMap.values) {
                            if (peer.ip.startsWith("bt:")) continue
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

    private fun isBluetoothEnabled(): Boolean {
        return try {
            val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            bluetoothManager?.adapter?.isEnabled == true
        } catch (_: Exception) {
            false
        }
    }

    fun refreshBluetoothPeers() {
        try {
            val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            val adapter = bluetoothManager?.adapter ?: return
            if (!adapter.isEnabled) return

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                if (ContextCompat.checkSelfPermission(
                        context,
                        Manifest.permission.BLUETOOTH_CONNECT
                    ) != PackageManager.PERMISSION_GRANTED
                ) {
                    return
                }
            }

            val bonded = adapter.bondedDevices ?: return
            val now = System.currentTimeMillis()
            var changed = false

            for (device in bonded) {
                val name = device.name ?: "Paired Device"
                val lowerName = name.lowercase()
                // 1. Device Class Check: Filter out audio/video (headphones, car, speakers), peripherals, wearables
                val majorClass = try { device.bluetoothClass?.majorDeviceClass } catch (_: Exception) { null }
                if (majorClass == BluetoothClass.Device.Major.AUDIO_VIDEO ||
                    majorClass == BluetoothClass.Device.Major.PERIPHERAL ||
                    majorClass == BluetoothClass.Device.Major.WEARABLE ||
                    majorClass == BluetoothClass.Device.Major.HEALTH
                ) {
                    continue
                }

                // 2. Keyword Filter: Exclude accessories, cars, audio devices
                if (lowerName.contains("controller") || lowerName.contains("gamepad") ||
                    lowerName.contains("mouse") || lowerName.contains("keyboard") ||
                    lowerName.contains("headset") || lowerName.contains("headphones") ||
                    lowerName.contains("earbuds") || lowerName.contains("airpods") ||
                    lowerName.contains("watch") || lowerName.contains("speaker") ||
                    lowerName.contains("beats") || lowerName.contains("buds") ||
                    lowerName.contains("sound") || lowerName.contains("audio") ||
                    lowerName.contains("tws") || lowerName.contains("renault") ||
                    lowerName.contains("car") || lowerName.contains("auto")
                ) {
                    continue
                }

                val addr = device.address
                val peerId = "bt_${addr.replace(":", "")}"
                val trusted = isPeerTrusted(peerId)
                val existing = peerMap.values.find {
                    it.name.equals(name, ignoreCase = true) || it.id == peerId ||
                        (it.fingerprint.isNotEmpty() && it.fingerprint.equals(addr, ignoreCase = true))
                }

                if (existing != null) {
                    val isLanAvailable = !existing.ip.startsWith("bt:") && existing.port > 0
                    peerMap[existing.id] = existing.copy(
                        transport = if (isLanAvailable) "HYBRID" else "BT",
                        fingerprint = addr,
                        isTrusted = trusted || existing.isTrusted,
                        lastSeen = now
                    )
                    changed = true
                } else {
                    val peer = DiscoveredPeer(
                        id = peerId,
                        name = name,
                        ip = "bt:$addr",
                        port = 0,
                        transport = "BT",
                        fingerprint = addr,
                        isTrusted = trusted,
                        lastSeen = now
                    )
                    peerMap[peer.id] = peer
                    changed = true
                }
            }

            if (changed) {
                updatePeersFlow()
            }
        } catch (_: Exception) {
        }
    }

    private fun startCleanup() {
        cleanupJob?.cancel()
        cleanupJob = scope.launch {
            while (isActive) {
                delay(3000)
                refreshBluetoothPeers()
                val now = System.currentTimeMillis()
                var changed = false
                val it = peerMap.entries.iterator()
                while (it.hasNext()) {
                    val entry = it.next()
                    if (!entry.value.id.startsWith("manual_") && (now - entry.value.lastSeen > 8000L)) {
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
