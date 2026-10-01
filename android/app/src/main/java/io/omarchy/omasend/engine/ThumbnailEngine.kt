package io.omarchy.omasend.engine

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Build
import java.io.ByteArrayOutputStream
import java.io.File

data class ThumbnailResult(
    val file: File?,
    val thumbnailBase64: String?,
    val width: Int = 0,
    val height: Int = 0
)

object ThumbnailEngine {
    const val TARGET_SIZE = 96
    const val QUALITY = 75
    const val THUMBNAIL_PREFIX = "data:image/webp;base64,"

    fun getThumbnailFile(context: Context, hash: String): File {
        val cacheDir = File(context.cacheDir, "clipboard_images")
        if (!cacheDir.exists()) {
            cacheDir.mkdirs()
        }
        return File(cacheDir, "${hash}_thumb.webp")
    }

    fun hasThumbnail(context: Context, hash: String): Boolean {
        if (hash.isBlank()) return false
        val file = getThumbnailFile(context, hash)
        return file.exists() && file.length() > 0
    }

    fun calculateInSampleSize(origWidth: Int, origHeight: Int, targetSize: Int = TARGET_SIZE): Int {
        var inSampleSize = 1
        val maxDim = maxOf(origWidth, origHeight)
        while ((maxDim / (inSampleSize * 2)) >= targetSize) {
            inSampleSize *= 2
        }
        return inSampleSize
    }

    fun encodeBase64(bytes: ByteArray): String {
        return try {
            android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
        } catch (_: Throwable) {
            java.util.Base64.getEncoder().encodeToString(bytes)
        }
    }

    fun decodeBase64(base64String: String): ByteArray? {
        val clean = if (base64String.contains(",")) {
            base64String.substringAfter(",")
        } else {
            base64String
        }
        return try {
            android.util.Base64.decode(clean.trim(), android.util.Base64.DEFAULT)
        } catch (_: Throwable) {
            try {
                java.util.Base64.getDecoder().decode(clean.trim())
            } catch (_: Throwable) {
                null
            }
        }
    }

    fun generateAndCacheThumbnail(
        context: Context,
        imageBytes: ByteArray,
        hash: String
    ): ThumbnailResult {
        if (imageBytes.isEmpty() || hash.isBlank()) {
            return ThumbnailResult(null, null)
        }

        return try {
            val thumbFile = getThumbnailFile(context, hash)

            // 1. Orijinal boyutları hesaplama
            val boundsOptions = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size, boundsOptions)
            val origWidth = boundsOptions.outWidth
            val origHeight = boundsOptions.outHeight

            if (origWidth <= 0 || origHeight <= 0) {
                return ThumbnailResult(null, null)
            }

            // 2. inSampleSize ile 96x96 hedefine indirgeme
            val inSampleSize = calculateInSampleSize(origWidth, origHeight, TARGET_SIZE)
            val decodeOptions = BitmapFactory.Options().apply {
                this.inSampleSize = inSampleSize
                inPreferredConfig = Bitmap.Config.ARGB_8888
            }

            val sampledBitmap = BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size, decodeOptions)
                ?: return ThumbnailResult(null, null)

            // 3. Boyut ölçekleme (maksimum boyut 96 olacak şekilde)
            val currentMax = maxOf(sampledBitmap.width, sampledBitmap.height)
            val finalBitmap = if (currentMax > TARGET_SIZE) {
                val scale = TARGET_SIZE.toFloat() / currentMax
                val targetW = (sampledBitmap.width * scale).toInt().coerceAtLeast(1)
                val targetH = (sampledBitmap.height * scale).toInt().coerceAtLeast(1)
                val scaled = Bitmap.createScaledBitmap(sampledBitmap, targetW, targetH, true)
                if (scaled != sampledBitmap) {
                    sampledBitmap.recycle()
                }
                scaled
            } else {
                sampledBitmap
            }

            val finalWidth = finalBitmap.width
            val finalHeight = finalBitmap.height

            // 4. WEBP_LOSSY (kalite 75) ile sıkıştırma
            val compressFormat = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Bitmap.CompressFormat.WEBP_LOSSY
            } else {
                @Suppress("DEPRECATION")
                Bitmap.CompressFormat.WEBP
            }

            val outputStream = ByteArrayOutputStream()
            finalBitmap.compress(compressFormat, QUALITY, outputStream)
            val webpBytes = outputStream.toByteArray()
            finalBitmap.recycle()

            // 5. cacheDir/clipboard_images/<hash>_thumb.webp konumuna atomik yazma
            val cacheDir = thumbFile.parentFile ?: File(context.cacheDir, "clipboard_images")
            if (!cacheDir.exists()) {
                cacheDir.mkdirs()
            }
            val tempFile = File(cacheDir, "${hash}_thumb.webp.tmp")
            tempFile.writeBytes(webpBytes)
            tempFile.renameTo(thumbFile)
            thumbFile.setLastModified(System.currentTimeMillis())

            // 6. thumbnailBase64 üretme
            val base64Raw = encodeBase64(webpBytes)
            val thumbnailBase64 = "$THUMBNAIL_PREFIX$base64Raw"

            ThumbnailResult(
                file = thumbFile,
                thumbnailBase64 = thumbnailBase64,
                width = finalWidth,
                height = finalHeight
            )
        } catch (_: Throwable) {
            ThumbnailResult(null, null)
        }
    }
}
