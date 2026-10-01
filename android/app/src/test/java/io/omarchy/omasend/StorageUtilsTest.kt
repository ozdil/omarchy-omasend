package io.omarchy.omasend

import io.omarchy.omasend.network.StorageUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StorageUtilsTest {

    @Test
    fun testSanitizeFilename_Normal() {
        assertEquals("document.pdf", StorageUtils.sanitizeFilename("document.pdf"))
        assertEquals("my_archive_2026.tar.gz", StorageUtils.sanitizeFilename("my_archive_2026.tar.gz"))
        assertEquals("turkce_belge_şğüçöı.txt", StorageUtils.sanitizeFilename("turkce_belge_şğüçöı.txt"))
    }

    @Test
    fun testSanitizeFilename_DirectoryTraversalAndNullBytes() {
        val traversed = StorageUtils.sanitizeFilename("../../etc/passwd")
        assertFalse(traversed.contains("/"))
        assertFalse(traversed.contains(".."))

        val nullInjected = StorageUtils.sanitizeFilename("safe\u0000file.png")
        assertFalse(nullInjected.contains("\u0000"))
    }

    @Test
    fun testSanitizeFilename_ReservedNames() {
        val conFile = StorageUtils.sanitizeFilename("CON.txt")
        assertTrue(conFile.startsWith("file_"))

        val nulFile = StorageUtils.sanitizeFilename("NUL")
        assertTrue(nulFile.startsWith("file_"))

        val auxFile = StorageUtils.sanitizeFilename("AUX.pdf")
        assertTrue(auxFile.startsWith("file_"))
    }

    @Test
    fun testSanitizeFilename_EmptyOrDotsOnly() {
        assertTrue(StorageUtils.sanitizeFilename("").startsWith("file_"))
        assertTrue(StorageUtils.sanitizeFilename("...").startsWith("file_"))
        assertTrue(StorageUtils.sanitizeFilename(" . ").startsWith("file_"))
    }

    @Test
    fun testStorageUtilsStreamingConstants() {
        assertEquals(10L * 1024 * 1024 * 1024L, StorageUtils.MAX_FILE_SIZE)
        assertEquals(128 * 1024, StorageUtils.STREAM_CHUNK_SIZE)
        assertEquals(null, StorageUtils.incomingTransferMetrics.value)
    }
}
