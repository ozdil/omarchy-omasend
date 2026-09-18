package io.omarchy.omasend.network

import android.Manifest
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import io.omarchy.omasend.model.DiscoveredPeer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.io.InputStream
import java.util.UUID

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
        if (!NetworkUtils.isPrivateOrLocalIp(ipCandidate)) return null
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

    val OBEX_OPP_UUID: UUID = UUID.fromString("00001105-0000-1000-8000-00805F9B34FB")

    /**
     * Directly transfers a file stream to a paired Bluetooth device using standard RFCOMM OBEX (Object Push Profile).
     * Connects directly to the target device's OBEX service, avoiding any secondary device chooser dialogs.
     */
    suspend fun sendViaBluetoothDirectObex(
        context: Context,
        targetMac: String,
        fileName: String,
        fileSize: Long,
        inputStream: InputStream,
        onProgress: suspend (bytesSent: Long, totalBytes: Long, percent: Int) -> Unit
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val cleanMac = targetMac.removePrefix("bt:").trim()
        if (cleanMac.isEmpty()) {
            return@withContext Result.failure(IllegalArgumentException("Hedef Bluetooth adresi boş"))
        }

        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager
        val adapter = bluetoothManager?.adapter
            ?: return@withContext Result.failure(IllegalStateException("Bluetooth donanımı bulunamadı"))

        if (!adapter.isEnabled) {
            return@withContext Result.failure(IllegalStateException("Bluetooth kapalı"))
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                return@withContext Result.failure(SecurityException("Bluetooth bağlantı izni verilmedi"))
            }
        }

        val device = try {
            adapter.getRemoteDevice(cleanMac)
        } catch (e: Exception) {
            return@withContext Result.failure(IllegalArgumentException("Geçersiz Bluetooth MAC adresi: $cleanMac", e))
        }

        var socket: BluetoothSocket? = null
        try {
            try { adapter.cancelDiscovery() } catch (_: Exception) {}

            socket = try {
                device.createInsecureRfcommSocketToServiceRecord(OBEX_OPP_UUID)
            } catch (_: Exception) {
                device.createRfcommSocketToServiceRecord(OBEX_OPP_UUID)
            }
            socket.connect()

            val out = socket.outputStream
            val `in` = socket.inputStream

            // 1. OBEX CONNECT (Opcode 0x80, Length = 7)
            val connectPacket = byteArrayOf(
                0x80.toByte(),
                0x00.toByte(), 0x07.toByte(),
                0x10.toByte(),
                0x00.toByte(),
                0x20.toByte(), 0x00.toByte()
            )
            out.write(connectPacket)
            out.flush()

            val connectResp = ByteArray(256)
            val connectRead = `in`.read(connectResp)
            if (connectRead < 3 || (connectResp[0].toInt() and 0xFF) != 0xA0) {
                val code = if (connectRead > 0) (connectResp[0].toInt() and 0xFF) else -1
                return@withContext Result.failure(IOException("OBEX bağlantısı kurulamadı (kod: $code)"))
            }

            var maxPacketSize = 8192
            if (connectRead >= 7) {
                val serverMax = ((connectResp[5].toInt() and 0xFF) shl 8) or (connectResp[6].toInt() and 0xFF)
                if (serverMax in 255..65535) {
                    maxPacketSize = minOf(serverMax, 8192)
                }
            }

            // 2. OBEX PUT Headers
            val nameBytes = fileName.toByteArray(Charsets.UTF_16BE)
            val nameHeaderLength = nameBytes.size + 2 + 3
            val nameHeader = ByteArray(nameHeaderLength).apply {
                this[0] = 0x01.toByte()
                this[1] = ((nameHeaderLength shr 8) and 0xFF).toByte()
                this[2] = (nameHeaderLength and 0xFF).toByte()
                System.arraycopy(nameBytes, 0, this, 3, nameBytes.size)
                this[nameHeaderLength - 2] = 0x00.toByte()
                this[nameHeaderLength - 1] = 0x00.toByte()
            }

            val lengthHeader = byteArrayOf(
                0xC3.toByte(),
                ((fileSize shr 24) and 0xFF).toByte(),
                ((fileSize shr 16) and 0xFF).toByte(),
                ((fileSize shr 8) and 0xFF).toByte(),
                (fileSize and 0xFF).toByte()
            )

            val fileHeaders = nameHeader + lengthHeader
            var bytesSent = 0L
            val buffer = ByteArray(maxOf(512, maxPacketSize - 64))
            var isFirstPacket = true

            while (true) {
                val readCount = inputStream.read(buffer)
                val isEof = readCount == -1 || (bytesSent + (if (readCount > 0) readCount else 0) >= fileSize)
                val chunkLength = if (readCount > 0) readCount else 0

                val opcode = if (isEof) 0x82.toByte() else 0x02.toByte()
                val bodyHeaderId = if (isEof) 0x49.toByte() else 0x48.toByte()

                val bodyHeaderLength = chunkLength + 3
                val extraHeaders = if (isFirstPacket) fileHeaders else byteArrayOf()
                val packetLength = 3 + extraHeaders.size + bodyHeaderLength

                val packet = ByteArray(packetLength)
                packet[0] = opcode
                packet[1] = ((packetLength shr 8) and 0xFF).toByte()
                packet[2] = (packetLength and 0xFF).toByte()

                var offset = 3
                if (extraHeaders.isNotEmpty()) {
                    System.arraycopy(extraHeaders, 0, packet, offset, extraHeaders.size)
                    offset += extraHeaders.size
                }

                packet[offset] = bodyHeaderId
                packet[offset + 1] = ((bodyHeaderLength shr 8) and 0xFF).toByte()
                packet[offset + 2] = (bodyHeaderLength and 0xFF).toByte()
                offset += 3

                if (chunkLength > 0) {
                    System.arraycopy(buffer, 0, packet, offset, chunkLength)
                    bytesSent += chunkLength
                }

                out.write(packet)
                out.flush()

                val resp = ByteArray(64)
                val respCount = `in`.read(resp)
                if (respCount <= 0) {
                    return@withContext Result.failure(IOException("OBEX sunucu yanıt vermedi"))
                }
                val respCode = resp[0].toInt() and 0xFF
                if (isEof) {
                    if (respCode != 0xA0 && respCode != 0x90) {
                        return@withContext Result.failure(IOException("OBEX dosya tamamlanamadı (kod: $respCode)"))
                    }
                } else {
                    if (respCode != 0x90 && respCode != 0xA0) {
                        return@withContext Result.failure(IOException("OBEX paket reddedildi (kod: $respCode)"))
                    }
                }

                isFirstPacket = false
                val percent = if (fileSize > 0) ((bytesSent * 100) / fileSize).toInt().coerceIn(0, 100) else 0
                onProgress(bytesSent, fileSize, percent)

                if (isEof) break
            }

            // 3. OBEX DISCONNECT (Opcode 0x81, Length = 3)
            try {
                out.write(byteArrayOf(0x81.toByte(), 0x00.toByte(), 0x03.toByte()))
                out.flush()
            } catch (_: Exception) {}

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }

    /**
     * Shares file(s) or text payload using Android's native Bluetooth service.
     */
    fun sendViaBluetooth(
        context: Context,
        uris: List<Uri>,
        textPayload: String? = null,
        targetMac: String? = null
    ): Boolean {
        val intent = Intent().apply {
            action = if (uris.size > 1) Intent.ACTION_SEND_MULTIPLE else Intent.ACTION_SEND
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

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

            if (!targetMac.isNullOrBlank()) {
                val cleanMac = targetMac.removePrefix("bt:")
                try {
                    val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager
                    val adapter = bluetoothManager?.adapter
                    val device = adapter?.getRemoteDevice(cleanMac)
                    if (device != null) {
                        putExtra("android.bluetooth.device.extra.DEVICE", device)
                    }
                } catch (_: Exception) {}
            }
        }

        return try {
            val btIntent = Intent(intent).apply {
                setPackage("com.android.bluetooth")
            }
            context.startActivity(btIntent)
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
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

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
            val chooser = Intent.createChooser(intent, chooserTitle).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(chooser)
            true
        } catch (_: Exception) {
            false
        }
    }
}
