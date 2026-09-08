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
}
