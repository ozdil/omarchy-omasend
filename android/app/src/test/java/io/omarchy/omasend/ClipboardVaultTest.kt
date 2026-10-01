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
}
