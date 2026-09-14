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
     * Shares file(s) or text payload using Bluetooth OPP or falls back to system share sheet.
     * Grants URI read permission via ClipData to satisfy Android 7+ / 11+ / 14+ requirements.
     */
    fun sendViaBluetooth(
        context: Context,
        uris: List<Uri>,
        textPayload: String? = null,
        targetMac: String? = null
    ): Boolean {
        val mimeType = when {
            uris.isNotEmpty() -> context.contentResolver.getType(uris.first()) ?: "*/*"
            !textPayload.isNullOrBlank() -> "text/plain"
            else -> "*/*"
        }

        val baseIntent = buildShareIntent(context, uris, textPayload, mimeType)

        // If target MAC is provided and valid, try attaching BluetoothDevice extra
        if (!targetMac.isNullOrBlank() && targetMac.contains(":")) {
            try {
                val btManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager
                val adapter = btManager?.adapter
                if (adapter != null && adapter.isEnabled) {
                    val device = adapter.getRemoteDevice(targetMac.trim())
                    if (device != null) {
                        baseIntent.putExtra(android.bluetooth.BluetoothDevice.EXTRA_DEVICE, device)
                        baseIntent.putExtra("android.bluetooth.device.extra.DEVICE", device)
                    }
                }
            } catch (_: Exception) {
            }
        }

        // Try to locate dedicated Bluetooth OPP activity on the device
        val pm = context.packageManager
        val candidates = try {
            pm.queryIntentActivities(baseIntent, android.content.pm.PackageManager.MATCH_DEFAULT_ONLY)
        } catch (_: Exception) {
            emptyList()
        }

        val btActivity = candidates.firstOrNull { info ->
            val pkg = info.activityInfo.packageName.lowercase()
            val name = info.activityInfo.name.lowercase()
            (pkg.contains("bluetooth") || name.contains("bluetooth") || pkg.contains("opp") || name.contains("opp")) &&
            !pkg.contains("wear")
        }

        if (btActivity != null) {
            try {
                val directBtIntent = Intent(baseIntent).apply {
                    component = android.content.ComponentName(btActivity.activityInfo.packageName, btActivity.activityInfo.name)
                }
                context.startActivity(directBtIntent)
                return true
            } catch (_: Exception) {
                try {
                    val pkgIntent = Intent(baseIntent).apply {
                        setPackage(btActivity.activityInfo.packageName)
                    }
                    context.startActivity(pkgIntent)
                    return true
                } catch (_: Exception) {
                }
            }
        }

        // Fallback: System chooser targeting Bluetooth / Nearby Share
        return shareViaSystem(context, uris, textPayload, "Bluetooth / Paylaş")
    }

    /**
     * Opens the standard Android system share sheet for cross-app sharing.
     */
    fun shareViaSystem(
        context: Context,
        uris: List<Uri>,
        textPayload: String? = null,
        chooserTitle: String = "Paylaş"
    ): Boolean {
        return try {
            val mimeType = when {
                uris.isNotEmpty() -> context.contentResolver.getType(uris.first()) ?: "*/*"
                !textPayload.isNullOrBlank() -> "text/plain"
                else -> "*/*"
            }
            val intent = buildShareIntent(context, uris, textPayload, mimeType)
            val chooser = Intent.createChooser(intent, chooserTitle).apply {
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                if (context !is android.app.Activity) {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            }
            context.startActivity(chooser)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun buildShareIntent(
        context: Context,
        uris: List<Uri>,
        textPayload: String?,
        mimeType: String
    ): Intent {
        val intent = Intent().apply {
            action = if (uris.size > 1) Intent.ACTION_SEND_MULTIPLE else Intent.ACTION_SEND
            type = mimeType
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            if (context !is android.app.Activity) {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            if (uris.size > 1) {
                putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris))
                val clipData = android.content.ClipData.newUri(context.contentResolver, "file_0", uris[0])
                for (i in 1 until uris.size) {
                    clipData.addItem(android.content.ClipData.Item(uris[i]))
                }
                this.clipData = clipData
            } else if (uris.isNotEmpty()) {
                val singleUri = uris.first()
                putExtra(Intent.EXTRA_STREAM, singleUri)
                clipData = android.content.ClipData.newUri(context.contentResolver, "file", singleUri)
            } else if (!textPayload.isNullOrBlank()) {
                putExtra(Intent.EXTRA_TEXT, textPayload)
                clipData = android.content.ClipData.newPlainText("text", textPayload)
            }
        }
        return intent
    }
}
