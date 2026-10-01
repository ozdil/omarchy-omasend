package io.omarchy.omasend.engine

import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.nio.ByteBuffer

class OmaIdQrAnalyzer(
    private val onOmaIdDetected: (String) -> Unit
) : ImageAnalysis.Analyzer {

    private val reader = MultiFormatReader().apply {
        val hints = mapOf<DecodeHintType, Any>(
            DecodeHintType.POSSIBLE_FORMATS to listOf(com.google.zxing.BarcodeFormat.QR_CODE),
            DecodeHintType.CHARACTER_SET to "UTF-8",
            DecodeHintType.TRY_HARDER to true
        )
        setHints(hints)
    }

    @Volatile
    private var isPaused = false

    @androidx.annotation.OptIn(ExperimentalGetImage::class)
    override fun analyze(imageProxy: ImageProxy) {
        if (isPaused) {
            imageProxy.close()
            return
        }

        try {
            val plane = imageProxy.planes.firstOrNull()
            if (plane != null) {
                val buffer: ByteBuffer = plane.buffer
                val data = ByteArray(buffer.remaining())
                buffer.get(data)

                val width = imageProxy.width
                val height = imageProxy.height

                // Planar YUV Luminance Source on Y plane (zero copy across chroma)
                val source = PlanarYUVLuminanceSource(
                    data,
                    width,
                    height,
                    0,
                    0,
                    width,
                    height,
                    false
                )

                val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
                val result = reader.decodeWithState(binaryBitmap)

                if (result != null && !result.text.isNullOrBlank()) {
                    val candidate = GalleryQrDecoder.parseOmaIdFromScannedPayload(result.text)
                    if (candidate != null) {
                        isPaused = true
                        onOmaIdDetected(candidate)
                    }
                }
            }
        } catch (_: NotFoundException) {
            // Normal scan frame without QR code
        } catch (_: Exception) {
            // Format or checksum errors on partial frames
        } finally {
            reader.reset()
            imageProxy.close()
        }
    }

    fun pause() {
        isPaused = true
    }

    fun resume() {
        isPaused = false
    }
}
