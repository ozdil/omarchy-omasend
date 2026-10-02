package io.omarchy.omasend

import io.omarchy.omasend.network.NetworkUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkUtilsTest {

    @Test
    fun testPrivateOrLocalIp_RFC1918() {
        // 10.0.0.0/8
        assertTrue(NetworkUtils.isPrivateOrLocalIp("10.0.0.1"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("10.255.255.254"))

        // 172.16.0.0/12
        assertTrue(NetworkUtils.isPrivateOrLocalIp("172.16.0.1"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("172.31.255.254"))
        assertFalse(NetworkUtils.isPrivateOrLocalIp("172.15.0.1"))
        assertFalse(NetworkUtils.isPrivateOrLocalIp("172.32.0.1"))

        // 192.168.0.0/16
        assertTrue(NetworkUtils.isPrivateOrLocalIp("192.168.1.1"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("192.168.100.250"))
        assertFalse(NetworkUtils.isPrivateOrLocalIp("192.169.1.1"))
    }

    @Test
    fun testPrivateOrLocalIp_LinkLocalAndLoopback() {
        assertTrue(NetworkUtils.isPrivateOrLocalIp("127.0.0.1"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("127.0.0.5"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("169.254.1.1"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("localhost"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("::1"))
    }

    @Test
    fun testPrivateOrLocalIp_PublicAndMalformed() {
        assertFalse(NetworkUtils.isPrivateOrLocalIp("8.8.8.8"))
        assertFalse(NetworkUtils.isPrivateOrLocalIp("1.1.1.1"))
        assertFalse(NetworkUtils.isPrivateOrLocalIp("142.250.180.206"))
        assertFalse(NetworkUtils.isPrivateOrLocalIp("999.999.999.999"))
        assertFalse(NetworkUtils.isPrivateOrLocalIp("invalid-ip"))
        assertFalse(NetworkUtils.isPrivateOrLocalIp(""))
    }

    @Test
    fun testFormatBytes() {
        assertEquals("500 B", NetworkUtils.formatBytes(500))
        assertEquals("1.0 KB", NetworkUtils.formatBytes(1024))
        assertEquals("1.5 MB", NetworkUtils.formatBytes(1572864))
        assertEquals("2.00 GB", NetworkUtils.formatBytes(2147483648))
    }

    @Test
    fun testSocketTuningConstants() {
        assertEquals(256 * 1024, NetworkUtils.SOCKET_BUFFER_SIZE)
        assertEquals(128 * 1024, NetworkUtils.IO_CHUNK_SIZE)
        assertEquals(0x08, NetworkUtils.IPTOS_THROUGHPUT)
    }

    @Test
    fun testConfigureHighThroughputSocket() {
        val server = java.net.ServerSocket(0)
        val port = server.localPort
        val clientSocket = java.net.Socket("127.0.0.1", port)
        val serverSideSocket = server.accept()

        NetworkUtils.configureHighThroughputSocket(clientSocket)
        NetworkUtils.configureHighThroughputSocket(serverSideSocket)

        assertTrue(clientSocket.tcpNoDelay)
        assertTrue(clientSocket.sendBufferSize > 0)
        assertTrue(clientSocket.receiveBufferSize > 0)

        clientSocket.close()
        serverSideSocket.close()
        server.close()
    }
}
