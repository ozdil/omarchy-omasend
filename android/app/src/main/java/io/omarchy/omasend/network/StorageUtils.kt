package io.omarchy.omasend.network

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import io.omarchy.omasend.model.TransferMetrics
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream

/**
 * StorageUtils
 *
 * Implements Scoped Storage persistence with ACM SIGCOMM streaming pipeline principles,
 * backpressure-conscious buffer management, and live StateFlow metrics.
 */
object StorageUtils {

    const val MAX_FILE_SIZE = 10L * 1024 * 1024 * 1024L // 10 GiB ceiling
    const val STREAM_CHUNK_SIZE = 128 * 1024 // 128 KiB chunked streaming

    private val RESERVED_NAMES = setOf(
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    )

    private val _incomingTransferMetrics = MutableStateFlow<TransferMetrics?>(null)
    val incomingTransferMetrics: StateFlow<TransferMetrics?> = _incomingTransferMetrics.asStateFlow()

    fun sanitizeFilename(raw: String): String {
        val trimmed = raw.replace("\u0000", "")
            .replace('/', '_')
            .replace('\\', '_')
            .filter { it.isLetterOrDigit() || it in ".-_ " }
            .trim()

        var clean = trimmed
        while (clean.contains("..")) {
            clean = clean.replace("..", "_")
        }

        val baseName = clean.substringBeforeLast('.', clean)
        if (clean.isEmpty() || clean.startsWith(".") || clean.all { it == '.' || it == '_' || it == '-' || it == ' ' } || RESERVED_NAMES.contains(baseName.uppercase())) {
            return "file_${System.currentTimeMillis()}"
        }
        return clean.take(180)
    }

    fun saveIncomingStream(
        context: Context,
        filename: String,
        inputStream: InputStream,
        totalBytes: Long,
        deadlineMs: Long = Long.MAX_VALUE,
        onProgress: ((bytesRead: Long, total: Long) -> Unit)? = null
    ): Pair<Boolean, String> {
        val progressCallback: ((Long, Long, TransferMetrics) -> Unit)? = if (onProgress != null) {
            { read, total, _ -> onProgress(read, total) }
        } else null

        return saveIncomingStreamWithMetrics(
            context = context,
            filename = filename,
            inputStream = inputStream,
            totalBytes = totalBytes,
            deadlineMs = deadlineMs,
            onProgressWithMetrics = progressCallback
        )
    }

    fun saveIncomingStreamWithMetrics(
        context: Context,
        filename: String,
        inputStream: InputStream,
        totalBytes: Long,
        deadlineMs: Long = Long.MAX_VALUE,
        onProgressWithMetrics: ((bytesRead: Long, total: Long, metrics: TransferMetrics) -> Unit)? = null
    ): Pair<Boolean, String> {
        if (totalBytes <= 0 || totalBytes > MAX_FILE_SIZE) {
            _incomingTransferMetrics.value = null
            return Pair(false, "Invalid or excessive file size ($totalBytes bytes)")
        }

        val usableSpace = context.filesDir.usableSpace
        if (usableSpace > 0 && usableSpace < (totalBytes + 64L * 1024 * 1024)) {
            _incomingTransferMetrics.value = null
            return Pair(false, "Insufficient storage space on device")
        }

        val cleanName = sanitizeFilename(filename)
        val speedCalculator = TransferSpeedCalculator(totalBytes)

        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val resolver = context.contentResolver
                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, cleanName)
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/OmaSend")
                    put(MediaStore.MediaColumns.IS_PENDING, 1)
                }

                val uri: Uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                    ?: return Pair(false, "Failed to create MediaStore entry")

                try {
                    resolver.openOutputStream(uri)?.let { rawOut ->
                        java.io.BufferedOutputStream(rawOut, STREAM_CHUNK_SIZE).use { out ->
                            pipeStreamWithBackpressure(inputStream, out, totalBytes, deadlineMs, speedCalculator, onProgressWithMetrics)
                        }
                    } ?: throw java.io.IOException("Cannot open output stream for MediaStore URI")

                    contentValues.clear()
                    contentValues.put(MediaStore.MediaColumns.IS_PENDING, 0)
                    resolver.update(uri, contentValues, null, null)
                    _incomingTransferMetrics.value = null
                    Pair(true, cleanName)
                } catch (e: Exception) {
                    _incomingTransferMetrics.value = null
                    // Rollback dangling pending entry
                    try { resolver.delete(uri, null, null) } catch (_: Exception) {}
                    throw e
                }
            } else {
                val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "OmaSend")
                if (!dir.exists()) dir.mkdirs()

                var target = File(dir, cleanName)
                if (!target.canonicalPath.startsWith(dir.canonicalPath)) {
                    _incomingTransferMetrics.value = null
                    return Pair(false, "Directory traversal detected")
                }

                if (target.exists()) {
                    val dot = cleanName.lastIndexOf('.')
                    val name = if (dot != -1) cleanName.substring(0, dot) else cleanName
                    val ext = if (dot != -1) cleanName.substring(dot) else ""
                    var counter = 1
                    while (target.exists() && counter < 1000) {
                        target = File(dir, "$name ($counter)$ext")
                        if (!target.canonicalPath.startsWith(dir.canonicalPath)) {
                            _incomingTransferMetrics.value = null
                            return Pair(false, "Directory traversal detected")
                        }
                        counter++
                    }
                }

                try {
                    java.io.BufferedOutputStream(FileOutputStream(target), STREAM_CHUNK_SIZE).use { out ->
                        pipeStreamWithBackpressure(inputStream, out, totalBytes, deadlineMs, speedCalculator, onProgressWithMetrics)
                    }
                    _incomingTransferMetrics.value = null
                    Pair(true, target.name)
                } catch (e: Exception) {
                    _incomingTransferMetrics.value = null
                    try { if (target.exists()) target.delete() } catch (_: Exception) {}
                    throw e
                }
            }
        } catch (e: Exception) {
            _incomingTransferMetrics.value = null
            Pair(false, e.message ?: "Unknown storage error")
        }
    }

    private fun pipeStreamWithBackpressure(
        input: InputStream,
        output: OutputStream,
        totalBytes: Long,
        deadlineMs: Long,
        speedCalculator: TransferSpeedCalculator,
        onProgress: ((bytesRead: Long, total: Long, metrics: TransferMetrics) -> Unit)?
    ) {
        val buffer = ByteArray(STREAM_CHUNK_SIZE)
        var totalRead = 0L
        var remaining = totalBytes
        var chunksSinceFlush = 0

        while (remaining > 0) {
            if (System.currentTimeMillis() > deadlineMs) {
                throw java.io.InterruptedIOException("File upload exceeded monotonic deadline")
            }
            val toRead = if (remaining < buffer.size) remaining.toInt() else buffer.size
            val read = input.read(buffer, 0, toRead)
            if (read == -1) break

            output.write(buffer, 0, read)
            totalRead += read
            remaining -= read
            chunksSinceFlush++

            // Backpressure: Periodic flush every 512 KiB (4 chunks) to prevent buffer accumulation
            if (chunksSinceFlush >= 4) {
                output.flush()
                chunksSinceFlush = 0
            }

            val metrics = speedCalculator.update(totalRead)
            _incomingTransferMetrics.value = metrics
            onProgress?.invoke(totalRead, totalBytes, metrics)
        }
        output.flush()
    }
}
