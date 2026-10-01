package io.omarchy.omasend

import io.omarchy.omasend.model.ClipboardEntry
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test
import java.security.MessageDigest
import java.util.UUID

class ClipboardVaultTest {

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = true
    }

    private fun computeSha256(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(text.toByteArray(Charsets.UTF_8))
        return hashBytes.joinToString("") { "%02x".format(it) }
    }

    @Test
    fun testClipboardEntrySerialization() {
        val entry = ClipboardEntry(
            id = "test-uuid-1",
            text = "https://omarchy.io/download",
            senderName = "omarchy-laptop",
            timestamp = 1700000000000L,
            isMine = false
        )

        val encoded = json.encodeToString(ClipboardEntry.serializer(), entry)
        assertTrue(encoded.contains("\"text\": \"https://omarchy.io/download\""))
        assertTrue(encoded.contains("\"senderName\": \"omarchy-laptop\""))
        assertTrue(encoded.contains("\"isMine\": false"))

        val decoded = json.decodeFromString<ClipboardEntry>(encoded)
        assertEquals("test-uuid-1", decoded.id)
        assertEquals("https://omarchy.io/download", decoded.text)
        assertEquals("omarchy-laptop", decoded.senderName)
        assertEquals(1700000000000L, decoded.timestamp)
        assertFalse(decoded.isMine)
    }

    @Test
    fun testClipboardEntryListSerialization() {
        val list = listOf(
            ClipboardEntry(id = "1", text = "Entry 1", senderName = "Phone", isMine = true),
            ClipboardEntry(id = "2", text = "Entry 2", senderName = "Desktop", isMine = false)
        )

        val encoded = json.encodeToString(ListSerializer(ClipboardEntry.serializer()), list)
        val decoded = json.decodeFromString(ListSerializer(ClipboardEntry.serializer()), encoded)

        assertEquals(2, decoded.size)
        assertEquals("Entry 1", decoded[0].text)
        assertTrue(decoded[0].isMine)
        assertEquals("Entry 2", decoded[1].text)
        assertFalse(decoded[1].isMine)
    }

    @Test
    fun testSha256HashCalculationAndInfiniteLoopPrevention() {
        val sampleText = "git clone https://github.com/omarchy/omarchy-omasend.git"
        val hash1 = computeSha256(sampleText)
        val hash2 = computeSha256(sampleText)

        assertEquals(64, hash1.length)
        assertEquals(hash1, hash2)

        // Verify different text produces different hash
        val differentText = "git clone https://github.com/omarchy/omarchy-desktop.git"
        val hashDiff = computeSha256(differentText)
        assertNotEquals(hash1, hashDiff)

        // Loop protection simulation:
        var lastReceivedHash = ""
        // 1. Remote peer pushes sampleText -> Server receives it and updates lastReceivedHash
        lastReceivedHash = hash1

        // 2. PrimaryClipListener on Android fires because clipboard changed
        val localClipText = sampleText
        val localClipHash = computeSha256(localClipText)

        // Loop detection: if localClipHash == lastReceivedHash, skip broadcasting back
        val shouldBroadcast = localClipHash != lastReceivedHash
        assertFalse("Echo loop must be prevented when clipboard originated from network", shouldBroadcast)

        // 3. User copies a new local text
        val userCopiedText = "pacman -Syu"
        val userCopiedHash = computeSha256(userCopiedText)
        val shouldBroadcastUserCopy = userCopiedHash != lastReceivedHash
        assertTrue("Locally generated clipboard must be broadcast to peers", shouldBroadcastUserCopy)
    }

    @Test
    fun testVaultCapacityCappedAt20Items() {
        val maxItems = 20
        val entries = mutableListOf<ClipboardEntry>()

        for (i in 1..35) {
            val entry = ClipboardEntry(
                id = UUID.randomUUID().toString(),
                text = "Clipboard text item $i",
                senderName = "Peer $i",
                timestamp = System.currentTimeMillis() + i,
                isMine = (i % 2 == 0)
            )
            entries.removeAll { it.text == entry.text }
            entries.add(0, entry)
            if (entries.size > maxItems) {
                entries.removeAt(entries.size - 1)
            }
        }

        assertEquals(maxItems, entries.size)
        assertEquals("Clipboard text item 35", entries.first().text)
        assertEquals("Clipboard text item 16", entries.last().text)
    }

    @Test
    fun testDuplicateTextDeduplicationInVault() {
        val entries = mutableListOf<ClipboardEntry>()

        val item1 = ClipboardEntry(id = "1", text = "Duplicate content", senderName = "Phone", isMine = true)
        val item2 = ClipboardEntry(id = "2", text = "Other content", senderName = "Phone", isMine = true)
        val item3 = ClipboardEntry(id = "3", text = "Duplicate content", senderName = "Desktop", isMine = false)

        for (item in listOf(item1, item2, item3)) {
            entries.removeAll { it.text == item.text }
            entries.add(0, item)
        }

        assertEquals(2, entries.size)
        assertEquals("Duplicate content", entries[0].text)
        assertEquals("Desktop", entries[0].senderName)
        assertFalse(entries[0].isMine)
        assertEquals("Other content", entries[1].text)
    }

    @Test
    fun testLruRingHashLoopProtection() {
        val hashRingCapacity = 64
        val hashRing = LinkedHashSet<String>()

        fun recordHash(hash: String) {
            hashRing.remove(hash)
            while (hashRing.size >= hashRingCapacity) {
                val it = hashRing.iterator()
                if (it.hasNext()) {
                    it.next()
                    it.remove()
                }
            }
            hashRing.add(hash)
        }

        // Record 100 hashes
        for (i in 1..100) {
            recordHash(computeSha256("text_$i"))
        }

        assertEquals(hashRingCapacity, hashRing.size)

        // Hashes 1..36 should have been evicted
        assertFalse(hashRing.contains(computeSha256("text_1")))
        assertFalse(hashRing.contains(computeSha256("text_36")))

        // Hashes 37..100 should be preserved
        assertTrue(hashRing.contains(computeSha256("text_37")))
        assertTrue(hashRing.contains(computeSha256("text_100")))
    }

    @Test
    fun testImageClipboardEntrySerialization() {
        val imageEntry = ClipboardEntry(
            id = "img-uuid-42",
            text = "[Görsel: screenshot.png]",
            senderName = "omarchy-arch",
            timestamp = 1710000000000L,
            isMine = false,
            contentType = "image/png",
            imageHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            imageSize = 1048576L,
            thumbnailBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
            width = 1920,
            height = 1080
        )

        val encoded = json.encodeToString(ClipboardEntry.serializer(), imageEntry)
        assertTrue(encoded.contains("\"contentType\": \"image/png\""))
        assertTrue(encoded.contains("\"imageHash\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\""))
        assertTrue(encoded.contains("\"imageSize\": 1048576"))
        assertTrue(encoded.contains("\"width\": 1920"))
        assertTrue(encoded.contains("\"height\": 1080"))

        val decoded = json.decodeFromString<ClipboardEntry>(encoded)
        assertEquals("img-uuid-42", decoded.id)
        assertEquals("[Görsel: screenshot.png]", decoded.text)
        assertEquals("image/png", decoded.contentType)
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", decoded.imageHash)
        assertEquals(1048576L, decoded.imageSize)
        assertEquals(1920, decoded.width)
        assertEquals(1080, decoded.height)
        assertFalse(decoded.isMine)
    }

    @Test
    fun testImageClipboardDeduplicationInVault() {
        val entries = mutableListOf<ClipboardEntry>()
        val imgHash = "hash-12345678"

        val item1 = ClipboardEntry(
            id = "img-1",
            text = "[Görsel]",
            senderName = "Desktop",
            isMine = false,
            contentType = "image/png",
            imageHash = imgHash,
            imageSize = 2048L
        )

        val item2 = ClipboardEntry(
            id = "img-2",
            text = "[Görsel Güncel]",
            senderName = "Phone",
            isMine = true,
            contentType = "image/png",
            imageHash = imgHash,
            imageSize = 2048L
        )

        // Deduplication rule: matching text or matching imageHash
        for (item in listOf(item1, item2)) {
            entries.removeAll {
                (it.imageHash != null && it.imageHash == item.imageHash) ||
                (it.text.isNotEmpty() && it.text == item.text)
            }
            entries.add(0, item)
        }

        assertEquals(1, entries.size)
        assertEquals("img-2", entries[0].id)
        assertTrue(entries[0].isMine)
        assertEquals(imgHash, entries[0].imageHash)
    }

    @Test
    fun testImageCacheLruEvictionSimulation() {
        val maxTotalSizeBytes = 50L * 1024L * 1024L // 50 MB
        val maxImageFiles = 20

        data class MockImageFile(val hash: String, val size: Long, val lastModified: Long)

        val files = mutableListOf<MockImageFile>()

        fun evictLruIfNeeded() {
            var totalSize = files.sumOf { it.size }
            var fileCount = files.size

            if (totalSize <= maxTotalSizeBytes && fileCount <= maxImageFiles) return

            // Sort oldest first
            files.sortBy { it.lastModified }

            val it = files.iterator()
            while (it.hasNext() && (totalSize > maxTotalSizeBytes || fileCount > maxImageFiles)) {
                val f = it.next()
                totalSize -= f.size
                fileCount--
                it.remove()
            }
        }

        // Add 25 image files of 1 MB each -> exceeds 20 file limit
        for (i in 1..25) {
            files.add(MockImageFile(hash = "hash_$i", size = 1024L * 1024L, lastModified = i.toLong()))
            evictLruIfNeeded()
        }

        assertEquals(maxImageFiles, files.size)
        // First 5 should have been evicted
        assertFalse(files.any { it.hash == "hash_1" })
        assertFalse(files.any { it.hash == "hash_5" })
        assertTrue(files.any { it.hash == "hash_6" })
        assertTrue(files.any { it.hash == "hash_25" })

        // Add 2 large 30 MB files -> exceeds 50 MB total size limit
        files.clear()
        files.add(MockImageFile(hash = "large_1", size = 30L * 1024L * 1024L, lastModified = 100L))
        files.add(MockImageFile(hash = "large_2", size = 30L * 1024L * 1024L, lastModified = 200L))
        evictLruIfNeeded()

        assertEquals(1, files.size)
        assertEquals("large_2", files.first().hash)
    }
}
