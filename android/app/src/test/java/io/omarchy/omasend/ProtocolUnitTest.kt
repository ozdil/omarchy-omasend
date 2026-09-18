package io.omarchy.omasend

import io.omarchy.omasend.model.P2pBeaconPacket
import io.omarchy.omasend.model.TransferFileInfo
import io.omarchy.omasend.model.TransferRequest
import io.omarchy.omasend.network.NetworkUtils
import io.omarchy.omasend.network.StorageUtils
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolUnitTest {

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    @Test
    fun testP2pBeaconSerializationMatchesOmarchyDesktop() {
        val packet = P2pBeaconPacket(
            magic = "OMASEND_P2P",
            v = 1,
            id = "android-device-123",
            name = "Pixel 8 Pro",
            ip = "192.168.1.55",
            port = 53317,
            mode = "ALL",
            bt = false,
            fp = "a1b2c3d4"
        )
        val serialized = json.encodeToString(P2pBeaconPacket.serializer(), packet)
        assertTrue(serialized.contains("\"magic\":\"OMASEND_P2P\""))
        assertTrue(serialized.contains("\"port\":53317"))

        val deserialized = json.decodeFromString<P2pBeaconPacket>(serialized)
        assertEquals("OMASEND_P2P", deserialized.magic)
        assertEquals("Pixel 8 Pro", deserialized.name)
        assertEquals(53317, deserialized.port)
    }

    @Test
    fun testTransferRequestSerialization() {
        val request = TransferRequest(
            sender_id = "device-456",
            sender_name = "Omarchy Laptop",
            sender_ip = "192.168.1.81",
            files = listOf(
                TransferFileInfo("photo.jpg", 1048576L)
            ),
            total_size_bytes = 1048576L
        )
        val encoded = json.encodeToString(TransferRequest.serializer(), request)
        val decoded = json.decodeFromString<TransferRequest>(encoded)

        assertEquals("device-456", decoded.sender_id)
        assertEquals(1, decoded.files.size)
        assertEquals("photo.jpg", decoded.files[0].name)
        assertEquals(1048576L, decoded.total_size_bytes)
    }

    @Test
    fun testFilenameSanitization() {
        assertEquals("normal_file.txt", StorageUtils.sanitizeFilename("normal_file.txt"))
        // Path traversal rejection
        val traversalResult = StorageUtils.sanitizeFilename("../../../etc/passwd")
        assertFalse(traversalResult.contains(".."))
        assertFalse(traversalResult.startsWith("/"))

        // Special characters filtered
        val specialResult = StorageUtils.sanitizeFilename("my:bad*file?name.png")
        assertEquals("mybadfilename.png", specialResult)
    }

    @Test
    fun testFormatBytes() {
        assertEquals("500 B", NetworkUtils.formatBytes(500))
        assertEquals("1.0 KB", NetworkUtils.formatBytes(1024))
        assertEquals("1.5 MB", NetworkUtils.formatBytes(1572864))
        assertEquals("2.00 GB", NetworkUtils.formatBytes(2147483648L))
    }

    @Test
    fun testClipboardPayloadSerializationWithAuth() {
        val payload = io.omarchy.omasend.model.ClipboardPayload(
            sender_id = "sender-789",
            sender_name = "Desktop",
            text = "secret clipboard text",
            pin = "123456",
            token = "session-tok-abc"
        )
        val encoded = json.encodeToString(io.omarchy.omasend.model.ClipboardPayload.serializer(), payload)
        assertTrue(encoded.contains("\"pin\":\"123456\""))
        assertTrue(encoded.contains("\"token\":\"session-tok-abc\""))

        val decoded = json.decodeFromString<io.omarchy.omasend.model.ClipboardPayload>(encoded)
        assertEquals("sender-789", decoded.sender_id)
        assertEquals("secret clipboard text", decoded.text)
        assertEquals("123456", decoded.pin)
        assertEquals("session-tok-abc", decoded.token)
    }

    @Test
    fun testNetworkScopeValidation() {
        assertTrue(NetworkUtils.isPrivateOrLocalIp("127.0.0.1"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("192.168.1.10"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("10.0.0.1"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("172.16.0.5"))
        assertTrue(NetworkUtils.isPrivateOrLocalIp("169.254.1.1"))

        // Public WAN IPs must be rejected
        assertFalse(NetworkUtils.isPrivateOrLocalIp("8.8.8.8"))
        assertFalse(NetworkUtils.isPrivateOrLocalIp("1.1.1.1"))
        assertFalse(NetworkUtils.isPrivateOrLocalIp("142.250.190.46"))
    }
}
