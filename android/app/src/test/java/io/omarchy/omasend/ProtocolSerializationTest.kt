package io.omarchy.omasend

import io.omarchy.omasend.model.ClipboardPayload
import io.omarchy.omasend.model.P2pBeaconPacket
import io.omarchy.omasend.model.TransferDecision
import io.omarchy.omasend.model.TransferFileInfo
import io.omarchy.omasend.model.TransferRequest
import io.omarchy.omasend.model.TransferResponse
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolSerializationTest {

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    @Test
    fun testP2pBeaconPacketSerialization() {
        val beacon = P2pBeaconPacket(
            magic = "OMASEND_P2P",
            v = 1,
            id = "android-node-01",
            name = "Pixel 8 Pro",
            ip = "192.168.1.50",
            port = 53317,
            mode = "ALL",
            oma_id = "1234-5678-9012-3456",
            fp = "1234-5678-9012-3456"
        )
        val raw = json.encodeToString(P2pBeaconPacket.serializer(), beacon)
        val decoded = json.decodeFromString<P2pBeaconPacket>(raw)

        assertEquals("OMASEND_P2P", decoded.magic)
        assertEquals("android-node-01", decoded.id)
        assertEquals("1234-5678-9012-3456", decoded.oma_id)
        assertEquals("1234-5678-9012-3456", decoded.fp)
    }

    @Test
    fun testTransferRequestSerialization() {
        val files = listOf(
            TransferFileInfo(name = "test.iso", size_bytes = 4294967296L),
            TransferFileInfo(name = "checksum.sha256", size_bytes = 64L)
        )
        val req = TransferRequest(
            sender_id = "sender-123",
            sender_name = "ArchLinux",
            sender_ip = "192.168.1.10",
            files = files,
            total_size_bytes = 4294967360L
        )

        val raw = json.encodeToString(TransferRequest.serializer(), req)
        val decoded = json.decodeFromString<TransferRequest>(raw)

        assertEquals(2, decoded.files.size)
        assertEquals(4294967360L, decoded.total_size_bytes)
        assertEquals("test.iso", decoded.files[0].name)
    }

    @Test
    fun testClipboardPayloadSerialization() {
        val payload = ClipboardPayload(
            sender_id = "device-a",
            sender_name = "OmaSend Client",
            text = "Secret Token 12345",
            pin = "482910",
            token = "session_token_xyz"
        )
        val raw = json.encodeToString(ClipboardPayload.serializer(), payload)
        val decoded = json.decodeFromString<ClipboardPayload>(raw)

        assertEquals("Secret Token 12345", decoded.text)
        assertEquals("482910", decoded.pin)
        assertEquals("session_token_xyz", decoded.token)
    }

    @Test
    fun testImageClipboardPayloadSerialization() {
        val payload = ClipboardPayload(
            sender_id = "device-laptop",
            sender_name = "Laptop",
            text = "[Görsel: capture.png]",
            pin = "123456",
            token = "auth_tok_abc",
            content_type = "image/png",
            image_hash = "abc123456789deadbeef",
            image_size = 2097152L,
            thumbnail_base64 = "base64thumb==",
            width = 2560,
            height = 1440,
            image_data_base64 = "base64fulldata=="
        )
        val raw = json.encodeToString(ClipboardPayload.serializer(), payload)
        val decoded = json.decodeFromString<ClipboardPayload>(raw)

        assertEquals("device-laptop", decoded.sender_id)
        assertEquals("image/png", decoded.content_type)
        assertEquals("abc123456789deadbeef", decoded.image_hash)
        assertEquals(2097152L, decoded.image_size)
        assertEquals("base64thumb==", decoded.thumbnail_base64)
        assertEquals(2560, decoded.width)
        assertEquals(1440, decoded.height)
        assertEquals("base64fulldata==", decoded.image_data_base64)
    }
}
