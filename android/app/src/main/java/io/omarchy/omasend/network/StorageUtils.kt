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

    fun sanitizeFilename(raw: String): String {
        val cleaned = raw.filter { it.isLetterOrDigit() || it in ".-_ " }.trim()
        return if (cleaned.isEmpty() || cleaned.startsWith(".") || cleaned.contains("..")) {
            "file_${System.currentTimeMillis()}"
        } else {
            cleaned.take(180)
        }
    }

    fun saveIncomingStream(
        context: Context,
        filename: String,
        inputStream: InputStream,
        totalBytes: Long,
        onProgress: ((bytesRead: Long, total: Long) -> Unit)? = null
    ): Pair<Boolean, String> {
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
                    pipeStream(inputStream, out, totalBytes, onProgress)
                }

                contentValues.clear()
                contentValues.put(MediaStore.MediaColumns.IS_PENDING, 0)
                resolver.update(uri, contentValues, null, null)
                Pair(true, cleanName)
            } else {
                val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "OmaSend")
                if (!dir.exists()) dir.mkdirs()

                var target = File(dir, cleanName)
                if (target.exists()) {
                    val dot = cleanName.lastIndexOf('.')
                    val name = if (dot != -1) cleanName.substring(0, dot) else cleanName
                    val ext = if (dot != -1) cleanName.substring(dot) else ""
                    var counter = 1
                    while (target.exists() && counter < 1000) {
                        target = File(dir, "$name ($counter)$ext")
                        counter++
                    }
                }

                FileOutputStream(target).use { out ->
                    pipeStream(inputStream, out, totalBytes, onProgress)
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
        onProgress: ((bytesRead: Long, total: Long) -> Unit)?
    ) {
        val buffer = ByteArray(65536)
        var totalRead = 0L
        var read: Int
        var remaining = totalBytes

        while (remaining > 0) {
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
