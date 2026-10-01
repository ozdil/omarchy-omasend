package io.omarchy.omasend

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import io.omarchy.omasend.crypto.OmaIdentity
import io.omarchy.omasend.engine.GalleryQrDecoder
import org.junit.Assert.*
import org.junit.Test

class QrScannerEngineTest {

    @Test
    fun testParseOmaIdFromVariousPayloadFormats() {
        val validId = OmaIdentity.generateRandomOmaId()
        val rawDigits = OmaIdentity.unformat(validId)

        // 1. Direct formatted string
        val parsed1 = GalleryQrDecoder.parseOmaIdFromScannedPayload(validId)
        assertEquals(validId, parsed1)

        // 2. Raw 16 digits
        val parsed2 = GalleryQrDecoder.parseOmaIdFromScannedPayload(rawDigits)
        assertEquals(validId, parsed2)

        // 3. omasend://identity/<id> deep link
        val parsed3 = GalleryQrDecoder.parseOmaIdFromScannedPayload("omasend://identity/$validId")
        assertEquals(validId, parsed3)

        // 4. omasend://pair?id=<id>&key=test
        val parsed4 = GalleryQrDecoder.parseOmaIdFromScannedPayload("omasend://pair?id=$validId&key=secret123")
        assertEquals(validId, parsed4)

        // 5. https URL scheme
        val parsed5 = GalleryQrDecoder.parseOmaIdFromScannedPayload("https://omasend.omarchy.io/pair?id=$validId")
        assertEquals(validId, parsed5)

        // 6. Invalid / Tampered OmaID
        val invalidPayload = "4921-8374-9281-9999" // bad Luhn checksum
        val parsedInvalid = GalleryQrDecoder.parseOmaIdFromScannedPayload(invalidPayload)
        assertNull(parsedInvalid)

        // 7. Random text without valid OmaID
        assertNull(GalleryQrDecoder.parseOmaIdFromScannedPayload("Hello World 12345"))
    }

    @Test
    fun testZxingQrCodeGenerationAndDecodingRoundtrip() {
        val validId = OmaIdentity.generateRandomOmaId()
        val payload = "omasend://identity/$validId"

        // Generate QR Code BitMatrix
        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(payload, BarcodeFormat.QR_CODE, 200, 200)

        val width = bitMatrix.width
        val height = bitMatrix.height
        val pixels = IntArray(width * height)

        for (y in 0 until height) {
            for (x in 0 until width) {
                pixels[y * width + x] = if (bitMatrix.get(x, y)) Color.BLACK else Color.WHITE
            }
        }

        // Decode using RGBLuminanceSource
        val source = RGBLuminanceSource(width, height, pixels)
        val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
        val reader = MultiFormatReader()
        val result = reader.decode(binaryBitmap)

        assertNotNull(result)
        assertEquals(payload, result.text)

        val parsedId = GalleryQrDecoder.parseOmaIdFromScannedPayload(result.text)
        assertEquals(validId, parsedId)
    }
}
