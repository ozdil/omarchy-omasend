package io.omarchy.omasend.network

import android.content.Context
import android.os.Build
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.UUID

object NetworkUtils {
    const val PORT: Int = 53317

    fun getLocalIpAddress(): String {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return "127.0.0.1"
            for (iface in interfaces) {
                if (iface.isLoopback || !iface.isUp) continue
                val name = iface.name.lowercase()
                if (name.startsWith("tun") || name.startsWith("dummy") || name.startsWith("p2p")) continue

                for (addr in iface.inetAddresses) {
                    if (!addr.isLoopbackAddress && addr is Inet4Address) {
                        val host = addr.hostAddress ?: continue
                        if (!host.startsWith("127.")) {
                            return host
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return "127.0.0.1"
    }

    fun getDeviceId(context: Context): String {
        val prefs = context.getSharedPreferences("omasend_prefs", Context.MODE_PRIVATE)
        var id = prefs.getString("device_id", null)
        if (id == null) {
            id = "android-" + UUID.randomUUID().toString().take(12)
            prefs.edit().putString("device_id", id).apply()
        }
        return id
    }

    fun getDeviceName(context: Context): String {
        val prefs = context.getSharedPreferences("omasend_prefs", Context.MODE_PRIVATE)
        return prefs.getString("device_name", null) ?: (Build.MANUFACTURER.replaceFirstChar { it.uppercase() } + " " + Build.MODEL)
    }

    fun setDeviceName(context: Context, name: String) {
        val prefs = context.getSharedPreferences("omasend_prefs", Context.MODE_PRIVATE)
        prefs.edit().putString("device_name", name.trim()).apply()
    }

    fun getDevicePin(context: Context): String {
        val prefs = context.getSharedPreferences("omasend_prefs", Context.MODE_PRIVATE)
        var pin = prefs.getString("device_pin", null)
        if (pin == null) {
            val randomNum = java.security.SecureRandom().nextInt(900000) + 100000
            pin = randomNum.toString()
            prefs.edit().putString("device_pin", pin).apply()
        }
        return pin
    }

    fun getDeviceSessionKey(context: Context): String {
        val prefs = context.getSharedPreferences("omasend_prefs", Context.MODE_PRIVATE)
        var key = prefs.getString("session_key", null)
        if (key == null) {
            key = UUID.randomUUID().toString().replace("-", "")
            prefs.edit().putString("session_key", key).apply()
        }
        return key
    }

    fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return String.format(java.util.Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format(java.util.Locale.US, "%.1f MB", mb)
        val gb = mb / 1024.0
        return String.format(java.util.Locale.US, "%.2f GB", gb)
    }

    /**
     * Strictly validates whether an IP address belongs to RFC 1918 private space,
     * RFC 3927 link-local, or loopback space.
     */
    fun isPrivateOrLocalAddress(addr: java.net.InetAddress): Boolean {
        if (addr.isLoopbackAddress || addr.isSiteLocalAddress || addr.isLinkLocalAddress) {
            return true
        }
        val host = addr.hostAddress ?: return false
        return isPrivateOrLocalIp(host)
    }

    /**
     * Validates an IPv4 or loopback string against RFC 1918, RFC 3927 link-local, or loopback.
     */
    fun isPrivateOrLocalIp(ip: String): Boolean {
        val raw = ip.trim()
        if (raw == "::1" || raw == "localhost" || raw == "127.0.0.1") return true
        val cleanIp = raw.substringBefore(':').trim()
        if (cleanIp == "127.0.0.1" || cleanIp == "localhost" || cleanIp == "::1") return true
        val parts = cleanIp.split('.')
        if (parts.size != 4) return false
        val octets = parts.map { it.toIntOrNull() ?: return false }
        if (octets.any { it !in 0..255 }) return false

        // 10.0.0.0/8 (RFC 1918)
        if (octets[0] == 10) return true
        // 172.16.0.0/12 (RFC 1918)
        if (octets[0] == 172 && octets[1] in 16..31) return true
        // 192.168.0.0/16 (RFC 1918)
        if (octets[0] == 192 && octets[1] == 168) return true
        // 169.254.0.0/16 (RFC 3927 Link-Local)
        if (octets[0] == 169 && octets[1] == 254) return true
        // 127.0.0.0/8 (Loopback)
        if (octets[0] == 127) return true

        return false
    }

    const val SOCKET_BUFFER_SIZE: Int = 256 * 1024 // 256 KiB socket buffer for IEEE 802.11 throughput
    const val IO_CHUNK_SIZE: Int = 128 * 1024 // 128 KiB chunked I/O stream alignment
    const val IPTOS_THROUGHPUT: Int = 0x08 // RFC 791/1349 Throughput optimization

    /**
     * Configures a socket with IEEE 802.11 wireless and TCP high-throughput options:
     * - TCP_NODELAY = true (disables Nagle algorithm to eliminate transmission latency spikes)
     * - SO_SNDBUF = 256 KiB
     * - SO_RCVBUF = 256 KiB
     * - IP Traffic Class / TOS = 0x08 (Throughput / WMM queue optimization)
     */
    fun configureHighThroughputSocket(socket: java.net.Socket) {
        try {
            socket.tcpNoDelay = true
            socket.sendBufferSize = SOCKET_BUFFER_SIZE
            socket.receiveBufferSize = SOCKET_BUFFER_SIZE
            socket.trafficClass = IPTOS_THROUGHPUT
        } catch (_: Exception) {
        }
    }

    /**
     * Acquires a high-performance Wi-Fi Lock to prevent IEEE 802.11 power saving throttling during transfers.
     */
    fun acquireHighPerfWifiLock(
        context: Context,
        tag: String = "OmaSend:HighPerfTransfer"
    ): android.net.wifi.WifiManager.WifiLock? {
        return try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? android.net.wifi.WifiManager
                ?: return null
            val lockMode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                android.net.wifi.WifiManager.WIFI_MODE_FULL_LOW_LATENCY
            } else {
                @Suppress("DEPRECATION")
                android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF
            }
            wifiManager.createWifiLock(lockMode, tag).apply {
                setReferenceCounted(false)
                acquire()
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Safely releases a Wi-Fi Lock.
     */
    fun releaseWifiLock(lock: android.net.wifi.WifiManager.WifiLock?) {
        try {
            if (lock != null && lock.isHeld) {
                lock.release()
            }
        } catch (_: Exception) {
        }
    }

    /**
     * Executes a block within the scope of a high-performance Wi-Fi Lock, ensuring guaranteed release.
     */
    inline fun <T> withHighPerfWifiLock(
        context: Context,
        tag: String = "OmaSend:HighPerfTransfer",
        block: () -> T
    ): T {
        val lock = acquireHighPerfWifiLock(context, tag)
        return try {
            block()
        } finally {
            releaseWifiLock(lock)
        }
    }

    fun computeSha256(bytes: ByteArray): String {
        return try {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val hashBytes = digest.digest(bytes)
            hashBytes.joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            bytes.contentHashCode().toString()
        }
    }

    fun computeSha256(text: String): String {
        return computeSha256(text.toByteArray(Charsets.UTF_8))
    }
}

