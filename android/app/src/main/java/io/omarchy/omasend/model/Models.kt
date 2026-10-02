package io.omarchy.omasend.model

import kotlinx.serialization.Serializable

@Serializable
data class P2pBeaconPacket(
    val magic: String = "OMASEND_P2P",
    val v: Int = 1,
    val id: String,
    val name: String,
    val ip: String,
    val port: Int = 53317,
    val mode: String = "ALL",
    val oma_id: String = "",
    val fp: String = ""
)

data class DiscoveredPeer(
    val id: String,
    val name: String,
    val ip: String,
    val port: Int = 53317,
    val transport: String = "LAN",
    val omaId: String = "",
    val fingerprint: String = "",
    val isTrusted: Boolean = false,
    val lastSeen: Long = System.currentTimeMillis()
)

@Serializable
data class TransferFileInfo(
    val name: String,
    val size_bytes: Long
)

@Serializable
data class TransferRequest(
    val sender_id: String,
    val sender_name: String,
    val sender_ip: String,
    val files: List<TransferFileInfo>,
    val total_size_bytes: Long
)

@Serializable
data class TransferResponse(
    val status: String,
    val token: String? = null,
    val error: String? = null
)

@Serializable
data class TransferDecision(
    val status: String
)

@Serializable
data class ClipboardPayload(
    val sender_id: String,
    val sender_name: String,
    val text: String = "",
    val pin: String? = null,
    val token: String? = null,
    val content_type: String = "text",
    val image_hash: String? = null,
    val image_size: Long? = null,
    val thumbnail_base64: String? = null,
    val width: Int? = null,
    val height: Int? = null,
    val image_data_base64: String? = null
)

@Serializable
data class ClipboardEntry(
    val id: String = java.util.UUID.randomUUID().toString(),
    val text: String = "",
    val senderName: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isMine: Boolean = false,
    val contentType: String = "text",
    val imageHash: String? = null,
    val imageSize: Long? = null,
    val thumbnailBase64: String? = null,
    val width: Int? = null,
    val height: Int? = null
)


sealed class TransferProgressState {
    object Idle : TransferProgressState()
    data class Requesting(val peerName: String, val fileName: String) : TransferProgressState()
    data class WaitingConsent(val peerName: String) : TransferProgressState()
    data class Transferring(
        val isUploading: Boolean,
        val peerName: String,
        val fileName: String,
        val bytesTransferred: Long,
        val totalBytes: Long,
        val percent: Int,
        val speedMBps: Double = 0.0,
        val etaSeconds: Long = 0L
    ) : TransferProgressState()
    data class Success(val message: String) : TransferProgressState()
    data class Error(val message: String) : TransferProgressState()
}

@Serializable
data class TransferMetrics(
    val bytesTransferred: Long = 0L,
    val totalBytes: Long = 0L,
    val percent: Int = 0,
    val speedMBps: Double = 0.0,
    val etaSeconds: Long = 0L,
    val isCompleted: Boolean = false
)

data class IncomingTransferPrompt(
    val token: String,
    val senderId: String,
    val senderName: String,
    val senderIp: String,
    val files: List<TransferFileInfo>,
    val totalSizeBytes: Long
)

enum class DiscoveryMode(val wireMode: String) {
    OFF("OFF"),
    KNOWN_PEERS("KNOWN"),
    EVERYONE("ALL")
}

