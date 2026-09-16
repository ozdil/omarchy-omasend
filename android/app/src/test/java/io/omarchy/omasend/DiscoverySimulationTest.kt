package io.omarchy.omasend

import io.omarchy.omasend.model.ClipboardPayload
import io.omarchy.omasend.model.DiscoveredPeer
import io.omarchy.omasend.model.DiscoveryMode
import io.omarchy.omasend.model.P2pBeaconPacket
import io.omarchy.omasend.model.TransferDecision
import io.omarchy.omasend.model.TransferFileInfo
import io.omarchy.omasend.model.TransferRequest
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

class DiscoverySimulationTest {

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    @Test
    fun testDiscoveryModeWireMapping() {
        assertEquals("OFF", DiscoveryMode.OFF.wireMode)
        assertEquals("KNOWN", DiscoveryMode.KNOWN_PEERS.wireMode)
        assertEquals("ALL", DiscoveryMode.EVERYONE.wireMode)
    }

    @Test
    fun testSimulatedPeerBeaconArrival() {
        val desktopBeaconJson = """
            {
                "magic": "OMASEND_P2P",
                "v": 1,
                "id": "arch-linux-desktop-99",
                "name": "Ozan ThinkPad Arch",
                "ip": "192.168.1.100",
                "port": 53317,
                "mode": "ALL",
                "bt": false,
                "fp": "sha256:abc12345"
            }
        """.trimIndent()

        val parsed = json.decodeFromString<P2pBeaconPacket>(desktopBeaconJson)
        assertEquals("OMASEND_P2P", parsed.magic)
        assertEquals(1, parsed.v)
        assertEquals("arch-linux-desktop-99", parsed.id)
        assertEquals("Ozan ThinkPad Arch", parsed.name)
        assertEquals("192.168.1.100", parsed.ip)
        assertEquals(53317, parsed.port)
        assertEquals("ALL", parsed.mode)
        assertFalse(parsed.bt)
        assertEquals("sha256:abc12345", parsed.fp)

        // Simulate converting beacon packet to DiscoveredPeer model
        val peer = DiscoveredPeer(
            id = parsed.id,
            name = parsed.name,
            ip = parsed.ip,
            port = parsed.port,
            transport = if (parsed.bt) "BT+LAN" else "LAN",
            fingerprint = parsed.fp,
            lastSeen = System.currentTimeMillis()
        )

        assertEquals("arch-linux-desktop-99", peer.id)
        assertEquals("LAN", peer.transport)
        assertTrue(peer.lastSeen > 0)
    }

    @Test
    fun testSelfLoopbackPacketRejectionSimulation() {
        val myId = "phone-self-uuid-1"
        val myIp = "192.168.1.55"

        val loopbackBeacon = P2pBeaconPacket(
            magic = "OMASEND_P2P",
            v = 1,
            id = myId,
            name = "My Phone",
            ip = myIp,
            port = 53317,
            mode = "ALL"
        )

        // Rejection logic verification
        val isSelf = loopbackBeacon.id == myId || loopbackBeacon.ip == myIp
        assertTrue("Self beacon packets MUST be rejected to avoid ghost peers", isSelf)
    }

    @Test
    fun testCorruptBeaconPacketHandling() {
        val foreignPacket = """{"protocol":"UNKNOWN_P2P","data":123}"""
        var parsed: P2pBeaconPacket? = null
        try {
            parsed = json.decodeFromString<P2pBeaconPacket>(foreignPacket)
        } catch (_: Exception) {
        }
        // Either throws or fails magic verification
        val isValid = parsed?.magic == "OMASEND_P2P"
        assertFalse("Foreign packets without OMASEND_P2P magic must be dropped", isValid)
    }

    @Test
    fun testSimulatedRadarSweepPhosphorPersistence() {
        // Test CRT phosphor fade logic:
        // When sweep passes angle, blip illuminates to peak (0.9-1.0) and fades over 90 degrees
        val blipAngle = 45f

        // Case 1: Sweep beam is exactly on the blip (45 degrees)
        val sweepAngleAtBlip = 45f
        val diffAtBlip = (sweepAngleAtBlip - blipAngle + 360f) % 360f
        assertEquals(0f, diffAtBlip, 0.001f)
        val alphaAtBlip = if (diffAtBlip < 90f) ((90f - diffAtBlip) / 90f) * 0.9f else 0.15f
        assertTrue("Blip should be near peak brightness when swept", alphaAtBlip >= 0.89f)

        // Case 2: Sweep beam has moved 45 degrees past the blip (90 degrees)
        val sweepAnglePast = 90f
        val diffPast = (sweepAnglePast - blipAngle + 360f) % 360f
        assertEquals(45f, diffPast, 0.001f)
        val alphaPast = if (diffPast < 90f) ((90f - diffPast) / 90f) * 0.9f else 0.15f
        assertTrue("Blip should have faded by ~50%", alphaPast in 0.40f..0.50f)

        // Case 3: Sweep beam has moved opposite the blip (225 degrees)
        val sweepAngleFar = 225f
        val diffFar = (sweepAngleFar - blipAngle + 360f) % 360f
        val alphaFar = if (diffFar < 90f) ((90f - diffFar) / 90f) * 0.9f else 0.15f
        assertEquals(0.15f, alphaFar, 0.001f)
    }

    @Test
    fun testRadarTrigonometryCoordinates() {
        val centerX = 130f
        val centerY = 130f
        val maxRadius = 120f
        val angleDeg = 90f // pointing directly downward in standard screen coords
        val distRatio = 0.5f

        val rad = angleDeg * PI / 180.0
        val bx = centerX + (maxRadius * distRatio * cos(rad)).toFloat()
        val by = centerY + (maxRadius * distRatio * sin(rad)).toFloat()

        assertEquals(130f, bx, 0.01f) // cos(90) = 0
        assertEquals(190f, by, 0.01f) // sin(90) = 1 -> 130 + 60 = 190
    }

    @Test
    fun testClipboardPayloadSimulation() {
        val payload = ClipboardPayload(
            sender_id = "phone-android-77",
            sender_name = "OmaSend Android",
            text = "https://ozanozdil.com/blog/omasend-airbridge"
        )
        val serialized = json.encodeToString(ClipboardPayload.serializer(), payload)
        val deserialized = json.decodeFromString<ClipboardPayload>(serialized)

        assertEquals("phone-android-77", deserialized.sender_id)
        assertEquals("OmaSend Android", deserialized.sender_name)
        assertEquals("https://ozanozdil.com/blog/omasend-airbridge", deserialized.text)
    }

    @Test
    fun testTransferHandshakeProtocolSimulation() {
        val files = listOf(
            TransferFileInfo("project_report.pdf", 5242880L),
            TransferFileInfo("diagram.png", 1048576L)
        )
        val req = TransferRequest(
            sender_id = "android-sender",
            sender_name = "Pixel Fold",
            sender_ip = "192.168.1.42",
            files = files,
            total_size_bytes = 6291456L
        )
        val reqJson = json.encodeToString(TransferRequest.serializer(), req)
        val parsedReq = json.decodeFromString<TransferRequest>(reqJson)

        assertEquals(2, parsedReq.files.size)
        assertEquals(6291456L, parsedReq.total_size_bytes)

        // Simulated Accept Decision
        val decision = TransferDecision(status = "ACCEPT")
        val decisionJson = json.encodeToString(TransferDecision.serializer(), decision)
        val parsedDecision = json.decodeFromString<TransferDecision>(decisionJson)
        assertEquals("ACCEPT", parsedDecision.status)
    }

    @Test
    fun testRfc1918AndLinkLocalIpValidation() {
        // RFC 1918 Private & Local IPs
        assertTrue(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("127.0.0.1"))
        assertTrue(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("localhost"))
        assertTrue(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("10.0.0.1"))
        assertTrue(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("10.255.255.254"))
        assertTrue(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("172.16.0.1"))
        assertTrue(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("172.31.255.254"))
        assertTrue(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("192.168.0.1"))
        assertTrue(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("192.168.1.100:53317"))
        assertTrue(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("169.254.1.1"))

        // Public / WAN IPs and invalid inputs MUST be rejected
        assertFalse(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("8.8.8.8"))
        assertFalse(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("1.1.1.1"))
        assertFalse(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("172.32.0.1"))
        assertFalse(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("192.169.1.1"))
        assertFalse(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("203.0.113.195"))
        assertFalse(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("invalid_host"))
        assertFalse(io.omarchy.omasend.network.NetworkUtils.isPrivateOrLocalIp("10.0.0.256"))
    }

    @Test
    fun testFilenameSanitizationAndPathTraversalDefense() {
        // Path traversal attempts
        val traversed = io.omarchy.omasend.network.StorageUtils.sanitizeFilename("../../etc/passwd")
        assertFalse(traversed.contains("/"))
        assertFalse(traversed.contains(".."))

        // Backslash traversal
        val backslashed = io.omarchy.omasend.network.StorageUtils.sanitizeFilename("..\\..\\windows\\cmd.exe")
        assertFalse(backslashed.contains("\\"))
        assertFalse(backslashed.contains(".."))

        // Null byte injection
        val nullInjected = io.omarchy.omasend.network.StorageUtils.sanitizeFilename("safe.jpg\u0000.exe")
        assertFalse(nullInjected.contains("\u0000"))

        // Hidden files or empty
        val hidden = io.omarchy.omasend.network.StorageUtils.sanitizeFilename(".bashrc")
        assertTrue(hidden.startsWith("file_"))

        // Legitimate file
        val legit = io.omarchy.omasend.network.StorageUtils.sanitizeFilename("photo_2026-09-16.png")
        assertEquals("photo_2026-09-16.png", legit)
    }

    @Test
    fun testParseConnectionEndpointNetworkScope() {
        // Valid private IP endpoints
        val local = io.omarchy.omasend.network.TransferBridge.parseConnectionEndpoint("192.168.1.50:53317")
        assertNotNull(local)
        assertEquals("192.168.1.50", local?.first)
        assertEquals(53317, local?.second)

        val uriFormat = io.omarchy.omasend.network.TransferBridge.parseConnectionEndpoint("omasend://10.0.0.5:8080")
        assertNotNull(uriFormat)
        assertEquals("10.0.0.5", uriFormat?.first)
        assertEquals(8080, uriFormat?.second)

        // Public / WAN endpoints MUST be strictly rejected
        val publicIp = io.omarchy.omasend.network.TransferBridge.parseConnectionEndpoint("8.8.8.8:53317")
        assertEquals(null, publicIp)

        val publicUri = io.omarchy.omasend.network.TransferBridge.parseConnectionEndpoint("http://1.1.1.1:53317")
        assertEquals(null, publicUri)
    }
}
