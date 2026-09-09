package io.omarchy.omasend.network

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import io.omarchy.omasend.model.DiscoveredPeer

object TransferBridge {

    /**
     * Generates a QR code bitmap for sharing the local OmaSend endpoint with nearby devices.
     */
    fun generateQrCode(content: String, size: Int = 512): Bitmap? {
        return try {
            val writer = QRCodeWriter()
            val bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size)
            val width = bitMatrix.width
            val height = bitMatrix.height
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
            for (x in 0 until width) {
                for (y in 0 until height) {
                    bitmap.setPixel(
                        x,
                        y,
                        if (bitMatrix.get(x, y)) android.graphics.Color.BLACK else android.graphics.Color.WHITE
                    )
                }
            }
            bitmap
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Strictly validates and parses a connection string (URL, IP:Port, or QR code content).
     * Rejects invalid formats, private key leaks, or non-network inputs.
     */
    fun parseConnectionEndpoint(raw: String): Pair<String, Int>? {
        val trimmed = raw.trim()
        val cleaned = when {
            trimmed.startsWith("http://", ignoreCase = true) -> trimmed.substring(7)
            trimmed.startsWith("https://", ignoreCase = true) -> trimmed.substring(8)
            trimmed.startsWith("omasend://", ignoreCase = true) -> trimmed.substring(10)
            else -> trimmed
        }.substringBefore('/').substringBefore('?')

        val parts = cleaned.split(':')
        val ipCandidate = parts.getOrNull(0)?.trim() ?: return null
        val portCandidate = parts.getOrNull(1)?.trim()?.toIntOrNull() ?: 53317

        if (!isValidIpv4(ipCandidate)) return null
        if (portCandidate !in 1024..65535) return null

        return Pair(ipCandidate, portCandidate)
    }

    /**
     * Validates IPv4 address using strict boundary checks on all 4 octets.
     */
    fun isValidIpv4(ip: String): Boolean {
        val parts = ip.split('.')
        if (parts.size != 4) return false
        for (part in parts) {
            val num = part.toIntOrNull() ?: return false
            if (num !in 0..255) return false
            if (part.length > 1 && part.startsWith('0')) return false // Reject octal ambiguity
        }
        return true
    }

    /**
     * Creates a synthetic DiscoveredPeer from a verified IP and Port for direct transfer.
     */
    fun createManualPeer(ip: String, port: Int = 53317): DiscoveredPeer {
        return DiscoveredPeer(
            id = "direct_${ip.replace('.', '_')}_$port",
            name = "Direct ($ip)",
            ip = ip,
            port = port,
            transport = "DIRECT",
            fingerprint = "",
            isTrusted = false,
            lastSeen = System.currentTimeMillis() + 3600000L
        )
    }

    /**
     * Shares file(s) or text payload using Android's native Bluetooth service.
     */
    fun sendViaBluetooth(context: Context, uris: List<Uri>, textPayload: String? = null): Boolean {
        val intent = Intent().apply {
            action = if (uris.size > 1) Intent.ACTION_SEND_MULTIPLE else Intent.ACTION_SEND
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            setPackage("com.android.bluetooth")

            if (uris.size > 1) {
                putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris))
                type = "*/*"
            } else if (uris.isNotEmpty()) {
                putExtra(Intent.EXTRA_STREAM, uris.first())
                type = context.contentResolver.getType(uris.first()) ?: "*/*"
            } else if (!textPayload.isNullOrBlank()) {
                putExtra(Intent.EXTRA_TEXT, textPayload)
                type = "text/plain"
            }
        }

        return try {
            context.startActivity(intent)
            true
        } catch (_: Exception) {
            // Fallback to system chooser targeting Bluetooth or general sharing
            shareViaSystem(context, uris, textPayload, "Share via Bluetooth")
        }
    }

    /**
     * Opens the standard Android system share sheet for cross-app sharing.
     */
    fun shareViaSystem(
        context: Context,
        uris: List<Uri>,
        textPayload: String? = null,
        chooserTitle: String = "Share via"
    ): Boolean {
        return try {
            val intent = Intent().apply {
                action = if (uris.size > 1) Intent.ACTION_SEND_MULTIPLE else Intent.ACTION_SEND
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)

                if (uris.size > 1) {
                    putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris))
                    type = "*/*"
                } else if (uris.isNotEmpty()) {
                    putExtra(Intent.EXTRA_STREAM, uris.first())
                    type = context.contentResolver.getType(uris.first()) ?: "*/*"
                } else if (!textPayload.isNullOrBlank()) {
                    putExtra(Intent.EXTRA_TEXT, textPayload)
                    type = "text/plain"
                }
            }
            context.startActivity(Intent.createChooser(intent, chooserTitle))
            true
        } catch (_: Exception) {
            false
        }
    }
}
