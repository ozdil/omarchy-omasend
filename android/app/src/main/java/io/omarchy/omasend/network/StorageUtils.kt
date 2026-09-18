package io.omarchy.omasend.network

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream

object StorageUtils {

    const val MAX_FILE_SIZE = 10L * 1024 * 1024 * 1024L // 10 GiB ceiling

    fun sanitizeFilename(raw: String): String {
        // Strip null bytes, slashes, backslashes, and control characters
        val cleanChars = raw.replace("\u0000", "")
            .replace('/', '_')
            .replace('\\', '_')
            .filter { it.isLetterOrDigit() || it in ".-_ " }
            .trim()

        return if (cleanChars.isEmpty() || cleanChars.startsWith(".") || cleanChars.contains("..")) {
            "file_${System.currentTimeMillis()}"
        } else {
            cleanChars.take(180)
        }
    }

    fun saveIncomingStream(
        context: Context,
        filename: String,
        inputStream: InputStream,
        totalBytes: Long,
        deadlineMs: Long = Long.MAX_VALUE,
        onProgress: ((bytesRead: Long, total: Long) -> Unit)? = null
    ): Pair<Boolean, String> {
        if (totalBytes <= 0 || totalBytes > MAX_FILE_SIZE) {
            return Pair(false, "Invalid or excessive file size ($totalBytes bytes)")
        }

        // Check available device storage before allocating (require at least file size + 64 MB buffer)
        val usableSpace = context.filesDir.usableSpace
        if (usableSpace > 0 && usableSpace < (totalBytes + 64L * 1024 * 1024)) {
            return Pair(false, "Insufficient storage space on device")
        }

        val cleanName = sanitizeFilename(filename)

        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val resolver = context.contentResolver
                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, cleanName)
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/OmaSend")
                    put(MediaStore.MediaColumns.IS_PENDING, 1)
                }

                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                    ?: return Pair(false, "Failed to create MediaStore entry")

                resolver.openOutputStream(uri)?.use { out ->
                    pipeStream(inputStream, out, totalBytes, deadlineMs, onProgress)
                }

                contentValues.clear()
                contentValues.put(MediaStore.MediaColumns.IS_PENDING, 0)
                resolver.update(uri, contentValues, null, null)
                Pair(true, cleanName)
            } else {
                val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "OmaSend")
                if (!dir.exists()) dir.mkdirs()

                var target = File(dir, cleanName)
                // Strict path traversal defense: target MUST reside within dir
                if (!target.canonicalPath.startsWith(dir.canonicalPath)) {
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
                            return Pair(false, "Directory traversal detected")
                        }
                        counter++
                    }
                }

                FileOutputStream(target).use { out ->
                    pipeStream(inputStream, out, totalBytes, deadlineMs, onProgress)
                }
                Pair(true, target.name)
            }
        } catch (e: Exception) {
            Pair(false, e.message ?: "Unknown storage error")
        }
    }

    private fun pipeStream(
        input: InputStream,
        output: OutputStream,
        totalBytes: Long,
        deadlineMs: Long,
        onProgress: ((bytesRead: Long, total: Long) -> Unit)?
    ) {
        val buffer = ByteArray(65536)
        var totalRead = 0L
        var read: Int
        var remaining = totalBytes

        while (remaining > 0) {
            if (System.currentTimeMillis() > deadlineMs) {
                throw java.io.InterruptedIOException("File upload exceeded monotonic deadline")
            }
            val toRead = if (remaining < buffer.size) remaining.toInt() else buffer.size
            read = input.read(buffer, 0, toRead)
            if (read == -1) break
            output.write(buffer, 0, read)
            totalRead += read
            remaining -= read
            onProgress?.invoke(totalRead, totalBytes)
        }
        output.flush()
    }
}
