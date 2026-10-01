package io.omarchy.omasend

import io.omarchy.omasend.crypto.OmaIdentity
import io.omarchy.omasend.network.WanDiscoveryEngine
import io.omarchy.omasend.network.WanEndpoint
import io.omarchy.omasend.network.NetworkTransportMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class WanDiscoveryEngineTest {

    @Test
    fun testStunBindingRequestStructure() {
        val identity = OmaIdentity("4829-1048-5729-1104")
        val engine = WanDiscoveryEngine(
            context = null,
            identityProvider = { identity }
        )
        val txId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
        val packet = engine.buildStunBindingRequest(txId)

        assertEquals("STUN packet should be 20 bytes", 20, packet.size)

        val buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)
        val msgType = buffer.short.toInt() and 0xFFFF
        val msgLen = buffer.short.toInt() and 0xFFFF
        val magicCookie = buffer.int

        assertEquals("Message type should be 0x0001 (Binding Request)", 0x0001, msgType)
        assertEquals("Length should be 0 for request without attributes", 0, msgLen)
        assertEquals("Magic cookie should be 0x2112A442", 0x2112A442, magicCookie)

        val readTxId = ByteArray(12)
        buffer.get(readTxId)
        assertTrue("Transaction ID must match", txId.contentEquals(readTxId))
    }

    @Test
    fun testParseStunXorMappedAddressIpv4() {
        val identity = OmaIdentity("4829-1048-5729-1104")
        val engine = WanDiscoveryEngine(
            context = null,
            identityProvider = { identity }
        )
        val txId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)

        // Build a mock STUN response with XOR-MAPPED-ADDRESS attribute
        // Expected IP: 198.51.100.42, Port: 53317 (0xD045)
        // XOR Port: 53317 ^ 0x2112 = 0xF157
        // IP 198.51.100.42 = 0xC633642A
        // XOR IP: 0xC633642A ^ 0x2112A442 = 0xE721C068
        val expectedIp = "198.51.100.42"
        val expectedPort = 53317

        val responseBuffer = ByteBuffer.allocate(32).order(ByteOrder.BIG_ENDIAN)
        responseBuffer.putShort(0x0101.toShort()) // Binding Success Response
        responseBuffer.putShort(12.toShort())     // Attribute length (8 bytes for XOR-MAPPED-ADDRESS + 4 bytes header)
        responseBuffer.putInt(0x2112A442)         // Magic Cookie
        responseBuffer.put(txId)                 // Transaction ID (12 bytes)

        // Attribute: XOR-MAPPED-ADDRESS
        responseBuffer.putShort(0x0020.toShort()) // Type: XOR-MAPPED-ADDRESS
        responseBuffer.putShort(8.toShort())      // Length: 8
        responseBuffer.put(0x00.toByte())        // Reserved
        responseBuffer.put(0x01.toByte())        // Family: IPv4 (0x01)
        responseBuffer.putShort((expectedPort xor 0x2112).toShort()) // XOR-Port

        val ipInt = ((198 shl 24) or (51 shl 16) or (100 shl 8) or 42)
        responseBuffer.putInt(ipInt xor 0x2112A442)

        val responseBytes = responseBuffer.array()
        val parsed = engine.parseStunBindingResponse(responseBytes, responseBytes.size, txId)

        assertNotNull("STUN parser should parse XOR-MAPPED-ADDRESS", parsed)
        assertEquals(expectedIp, parsed?.publicIp)
        assertEquals(expectedPort, parsed?.publicPort)
    }

    @Test
    fun testParseStunResponseTxIdMismatchRejection() {
        val identity = OmaIdentity("4829-1048-5729-1104")
        val engine = WanDiscoveryEngine(
            context = null,
            identityProvider = { identity }
        )
        val txId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
        val differentTxId = byteArrayOf(9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9)

        val responseBuffer = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
        responseBuffer.putShort(0x0101.toShort())
        responseBuffer.putShort(0.toShort())
        responseBuffer.putInt(0x2112A442)
        responseBuffer.put(differentTxId)

        val parsed = engine.parseStunBindingResponse(responseBuffer.array(), 20, txId)
        assertNull("Response with mismatched transaction ID should be rejected", parsed)
    }

    @Test
    fun testRendezvousBeaconCreationAndDecryption() {
        val identity = OmaIdentity("4829-1048-5729-1104")
        val engine = WanDiscoveryEngine(
            context = null,
            identityProvider = { identity }
        )

        val endpoint = WanEndpoint(publicIp = "203.0.113.195", publicPort = 53317)
        val beacon = engine.createAnnouncementBeacon(
            endpoint = endpoint,
            identity = identity,
            deviceName = "Omarchy Workstation",
            deviceId = "oma-dev-9988"
        )

        assertNotNull(beacon)
        assertEquals(identity.blindTopic, beacon.blindTopic)

        // Decrypt with correct OmaID
        val decrypted = engine.decryptBeacon(beacon, identity.formattedId)
        assertNotNull("Beacon should successfully decrypt with correct OmaID", decrypted)
        assertEquals("oma-dev-9988", decrypted?.deviceId)
        assertEquals("Omarchy Workstation", decrypted?.deviceName)
        assertEquals("203.0.113.195", decrypted?.wanIp)
        assertEquals(53317, decrypted?.wanPort)

        // Decrypt with incorrect OmaID must return null
        val wrongIdentity = OmaIdentity("1111-2222-3333-4444")
        val failedDecryption = engine.decryptBeacon(beacon, wrongIdentity.formattedId)
        assertNull("Decryption with wrong OmaID must fail and return null", failedDecryption)
    }

    @Test
    fun testRegisterRendezvousPeer() {
        val identity = OmaIdentity("4829-1048-5729-1104")
        val engine = WanDiscoveryEngine(
            context = null,
            identityProvider = { identity }
        )

        val payload = io.omarchy.omasend.network.RendezvousPayload(
            deviceId = "peer-alpha-123",
            deviceName = "Omarchy Laptop Remote",
            wanIp = "198.51.100.77",
            wanPort = 53317,
            localIp = "192.168.1.100",
            localPort = 53317,
            timestamp = System.currentTimeMillis(),
            omaId = identity.formattedId
        )

        val peer = engine.registerRendezvousPeer(payload)
        assertEquals("wan_peer-alpha-123", peer.id)
        assertEquals("Omarchy Laptop Remote", peer.name)
        assertEquals("198.51.100.77", peer.ip)
        assertEquals("WAN", peer.transport)
        assertTrue(peer.isTrusted)

        assertEquals(1, engine.status.value.rendezvousPeers.size)
        assertEquals(peer, engine.status.value.rendezvousPeers[0])
    }

    @Test
    fun testNetworkTransportModeSwitching() {
        val identity = OmaIdentity("4829-1048-5729-1104")
        val engine = WanDiscoveryEngine(
            context = null,
            identityProvider = { identity }
        )

        assertEquals(NetworkTransportMode.LAN, engine.status.value.mode)

        engine.setNetworkMode(NetworkTransportMode.WAN)
        assertEquals(NetworkTransportMode.WAN, engine.status.value.mode)

        engine.setNetworkMode(NetworkTransportMode.P2P_MESH)
        assertEquals(NetworkTransportMode.P2P_MESH, engine.status.value.mode)
    }
}
