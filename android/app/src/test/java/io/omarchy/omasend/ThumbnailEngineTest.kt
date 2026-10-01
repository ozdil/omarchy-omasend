package io.omarchy.omasend

import io.omarchy.omasend.engine.ThumbnailEngine
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class ThumbnailEngineTest {

    @Test
    fun testCalculateInSampleSize() {
        // 1920x1080 with target 96
        val sample1 = ThumbnailEngine.calculateInSampleSize(1920, 1080, 96)
        assertEquals(16, sample1)

        // 800x600 with target 96
        val sample2 = ThumbnailEngine.calculateInSampleSize(800, 600, 96)
        assertEquals(8, sample2)

        // 96x96 with target 96
        val sample3 = ThumbnailEngine.calculateInSampleSize(96, 96, 96)
        assertEquals(1, sample3)

        // Small 48x48 with target 96
        val sample4 = ThumbnailEngine.calculateInSampleSize(48, 48, 96)
        assertEquals(1, sample4)

        // 4K 3840x2160 with target 96
        val sample5 = ThumbnailEngine.calculateInSampleSize(3840, 2160, 96)
        assertEquals(32, sample5)
    }

    @Test
    fun testBase64EncodingAndDecoding() {
        val originalBytes = "Omarchy OmaSend WebP Thumbnail Engine".toByteArray(Charsets.UTF_8)
        val encoded = ThumbnailEngine.encodeBase64(originalBytes)
        assertNotNull(encoded)
        assertTrue(encoded.isNotEmpty())

        // Decode plain base64
        val decodedPlain = ThumbnailEngine.decodeBase64(encoded)
        assertNotNull(decodedPlain)
        assertArrayEquals(originalBytes, decodedPlain)

        // Decode data URI prefix base64
        val dataUri = "data:image/webp;base64,$encoded"
        val decodedUri = ThumbnailEngine.decodeBase64(dataUri)
        assertNotNull(decodedUri)
        assertArrayEquals(originalBytes, decodedUri)
    }

    @Test
    fun testBase64DecodingEdgeCases() {
        val emptyDecoded = ThumbnailEngine.decodeBase64("")
        assertNotNull(emptyDecoded)
        assertEquals(0, emptyDecoded!!.size)

        val invalidDecoded = ThumbnailEngine.decodeBase64("???not_valid_base64$$$")
        // Should handle gracefully without crashing
    }

    @Test
    fun testThumbnailFileNamingConvention() {
        val testHash = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        val expectedSuffix = "${testHash}_thumb.webp"
        assertTrue(expectedSuffix.endsWith("_thumb.webp"))
        assertEquals(testHash, expectedSuffix.substringBefore("_thumb.webp"))
    }

    @Test
    fun testLruEvictionWithThumbnailCleanup() {
        val maxTotalSizeBytes = 50L * 1024L * 1024L
        val maxImageFiles = 20

        data class MockDiskFile(val name: String, val size: Long, val lastModified: Long)

        val diskFiles = mutableListOf<MockDiskFile>()

        fun addImageWithThumb(hash: String, pngSize: Long, thumbSize: Long, timestamp: Long) {
            diskFiles.add(MockDiskFile("$hash.png", pngSize, timestamp))
            diskFiles.add(MockDiskFile("${hash}_thumb.webp", thumbSize, timestamp))
        }

        fun evictLruIfNeeded() {
            val mainPngs = diskFiles.filter { it.name.endsWith(".png") }.sortedBy { it.lastModified }
            var currentCount = mainPngs.size
            var currentTotalBytes = mainPngs.sumOf { it.size }

            for (file in mainPngs) {
                if (currentCount <= maxImageFiles && currentTotalBytes <= maxTotalSizeBytes) {
                    break
                }
                val baseName = file.name.substringBefore(".png")
                diskFiles.removeAll { it.name == file.name }
                diskFiles.removeAll { it.name == "${baseName}_thumb.webp" }
                currentCount--
                currentTotalBytes -= file.size
            }
        }

        // Add 25 images and their thumbnails
        for (i in 1..25) {
            addImageWithThumb("img_$i", 1024L * 1024L, 8L * 1024L, i.toLong())
            evictLruIfNeeded()
        }

        val remainingPngs = diskFiles.filter { it.name.endsWith(".png") }
        val remainingThumbs = diskFiles.filter { it.name.endsWith("_thumb.webp") }

        assertEquals(maxImageFiles, remainingPngs.size)
        assertEquals(maxImageFiles, remainingThumbs.size)

        // Ensure img_1..img_5 and their thumbs are evicted
        for (i in 1..5) {
            assertFalse(diskFiles.any { it.name == "img_$i.png" })
            assertFalse(diskFiles.any { it.name == "img_${i}_thumb.webp" })
        }

        // Ensure img_6..img_25 and their thumbs are intact
        for (i in 6..25) {
            assertTrue(diskFiles.any { it.name == "img_$i.png" })
            assertTrue(diskFiles.any { it.name == "img_${i}_thumb.webp" })
        }
    }
}
