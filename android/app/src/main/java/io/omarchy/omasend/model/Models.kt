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
    val bt: Boolean = false,
    val fp: String = ""
)

data class DiscoveredPeer(
    val id: String,
    val name: String,
    val ip: String,
    val port: Int = 53317,
    val transport: String = "LAN",
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
    val text: String
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
        val percent: Int
    ) : TransferProgressState()
    data class Success(val message: String) : TransferProgressState()
    data class Error(val message: String) : TransferProgressState()
}

data class IncomingTransferPrompt(
    val token: String,
    val senderId: String,
    val senderName: String,
    val senderIp: String,
    val files: List<TransferFileInfo>,
    val totalSizeBytes: Long
)
