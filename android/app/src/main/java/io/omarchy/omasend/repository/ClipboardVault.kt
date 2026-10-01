package io.omarchy.omasend.repository

import android.content.Context
import io.omarchy.omasend.OmaSendApp
import io.omarchy.omasend.model.ClipboardEntry
import io.omarchy.omasend.network.NetworkUtils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

class ClipboardVault private constructor(private val context: Context) {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val mutex = Mutex()
    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = true
    }

    private val vaultFile: File by lazy {
        File(context.filesDir, VAULT_FILE_NAME)
    }

    val imageCacheDir: File by lazy {
        File(context.cacheDir, "clipboard_images").apply {
            if (!exists()) {
                mkdirs()
            }
        }
    }

    private val _entries = MutableStateFlow<List<ClipboardEntry>>(emptyList())
    val entries: StateFlow<List<ClipboardEntry>> = _entries.asStateFlow()

    private val hashRingLock = Any()
    private val recentHashRing = LinkedHashSet<String>()

    private val _lastReceivedHash = AtomicReference<String>("")
    var lastReceivedHash: String
        get() = _lastReceivedHash.get()
        set(value) {
            _lastReceivedHash.set(value)
            if (value.isNotBlank()) {
                recordHash(value)
            }
        }

    init {
        loadEntries()
        evictLruCacheIfNeeded()
    }

    fun getImageFile(hash: String): File {
        if (!imageCacheDir.exists()) imageCacheDir.mkdirs()
        return File(imageCacheDir, "$hash.png")
    }

    fun getThumbnailFile(hash: String): File {
        return io.omarchy.omasend.engine.ThumbnailEngine.getThumbnailFile(context, hash)
    }

    fun hasThumbnail(hash: String): Boolean {
        return io.omarchy.omasend.engine.ThumbnailEngine.hasThumbnail(context, hash)
    }

    fun hasImage(hash: String): Boolean {
        if (hash.isBlank()) return false
        val file = getImageFile(hash)
        return file.exists() && file.length() > 0
    }

    fun evictLruCacheIfNeeded() {
        try {
            if (!imageCacheDir.exists()) return
            val files = imageCacheDir.listFiles()?.filter { it.isFile && !it.name.endsWith(".tmp") && !it.name.endsWith("_thumb.webp") } ?: return
            val maxImages = 20
            val maxTotalBytes = 50L * 1024L * 1024L // 50 MB
            val sorted = files.sortedBy { it.lastModified() }
            var currentTotalBytes = sorted.sumOf { it.length() }
            var currentCount = sorted.size

            for (file in sorted) {
                if (currentCount <= maxImages && currentTotalBytes <= maxTotalBytes) {
                    break
                }
                val size = file.length()
                val baseName = file.nameWithoutExtension
                if (file.delete()) {
                    currentCount--
                    currentTotalBytes -= size
                    val thumbFile = File(imageCacheDir, "${baseName}_thumb.webp")
                    if (thumbFile.exists()) {
                        thumbFile.delete()
                    }
                }
            }
        } catch (_: Exception) {}
    }

    fun saveImageBytes(hash: String, bytes: ByteArray): File {
        if (!imageCacheDir.exists()) imageCacheDir.mkdirs()
        val file = File(imageCacheDir, "$hash.png")
        val tmpFile = File(imageCacheDir, "$hash.tmp")
        tmpFile.writeBytes(bytes)
        tmpFile.renameTo(file)
        file.setLastModified(System.currentTimeMillis())

        try {
            io.omarchy.omasend.engine.ThumbnailEngine.generateAndCacheThumbnail(context, bytes, hash)
        } catch (_: Exception) {}

        evictLruCacheIfNeeded()
        return file
    }

    fun computeHash(text: String): String {
        return NetworkUtils.computeSha256(text)
    }

    fun computeImageHash(bytes: ByteArray): String {
        return NetworkUtils.computeSha256(bytes)
    }

    fun recordHash(hash: String) {
        if (hash.isBlank()) return
        synchronized(hashRingLock) {
            recentHashRing.remove(hash)
            while (recentHashRing.size >= HASH_RING_CAPACITY) {
                val it = recentHashRing.iterator()
                if (it.hasNext()) {
                    it.next()
                    it.remove()
                }
            }
            recentHashRing.add(hash)
        }
        _lastReceivedHash.set(hash)
    }

    fun isKnownHash(hash: String): Boolean {
        if (hash.isBlank()) return false
        return synchronized(hashRingLock) {
            recentHashRing.contains(hash)
        }
    }

    fun isDuplicateOrLoop(text: String): Boolean {
        if (text.isEmpty()) return true
        val currentHash = computeHash(text)
        return isKnownHash(currentHash)
    }

    fun updateLastReceivedHash(text: String) {
        val hash = computeHash(text)
        recordHash(hash)
    }

    fun addEntry(
        text: String = "",
        senderName: String,
        isMine: Boolean,
        contentType: String = "text",
        imageHash: String? = null,
        imageSize: Long? = null,
        thumbnailBase64: String? = null,
        width: Int? = null,
        height: Int? = null
    ): ClipboardEntry? {
        if (contentType == "text" && text.isBlank()) return null
        if (contentType == "image" && imageHash.isNullOrBlank()) return null

        val entry = ClipboardEntry(
            id = UUID.randomUUID().toString(),
            text = text,
            senderName = senderName,
            timestamp = System.currentTimeMillis(),
            isMine = isMine,
            contentType = contentType,
            imageHash = imageHash,
            imageSize = imageSize,
            thumbnailBase64 = thumbnailBase64,
            width = width,
            height = height
        )

        scope.launch {
            mutex.withLock {
                val current = _entries.value.toMutableList()
                if (contentType == "image" && imageHash != null) {
                    current.removeAll { it.contentType == "image" && it.imageHash == imageHash }
                } else if (text.isNotBlank()) {
                    current.removeAll { it.contentType == "text" && it.text == text }
                }
                current.add(0, entry)
                val trimmed = current.take(MAX_VAULT_ITEMS)
                _entries.value = trimmed
                saveEntries(trimmed)
            }
        }
        return entry
    }

    fun processIncomingClipboard(text: String, senderName: String): ClipboardEntry? {
        if (text.isBlank()) return null
        updateLastReceivedHash(text)
        return addEntry(text = text, senderName = senderName, isMine = false, contentType = "text")
    }

    fun processIncomingPayload(
        payload: io.omarchy.omasend.model.ClipboardPayload,
        peerIp: String = "",
        peerPort: Int = NetworkUtils.PORT,
        client: io.omarchy.omasend.network.OmaSendClient? = null
    ): ClipboardEntry? {
        if (payload.content_type == "image") {
            val hash = payload.image_hash ?: return null
            recordHash(hash)

            // 1. Direct write if payload contains image data (< 512 KiB)
            if (!payload.image_data_base64.isNullOrBlank()) {
                try {
                    val bytes = io.omarchy.omasend.engine.ThumbnailEngine.decodeBase64(payload.image_data_base64)
                    if (bytes != null && bytes.isNotEmpty()) {
                        saveImageBytes(hash, bytes)
                    }
                } catch (_: Exception) {}
            } else if (payload.image_size != null && payload.image_size <= 512 * 1024L && !payload.thumbnail_base64.isNullOrBlank()) {
                try {
                    val bytes = io.omarchy.omasend.engine.ThumbnailEngine.decodeBase64(payload.thumbnail_base64)
                    if (bytes != null && bytes.isNotEmpty()) {
                        saveImageBytes(hash, bytes)
                    }
                } catch (_: Exception) {}
            }

            // Cache incoming thumbnail payload directly to disk if available
            if (!payload.thumbnail_base64.isNullOrBlank()) {
                try {
                    val thumbFile = getThumbnailFile(hash)
                    if (!thumbFile.exists() || thumbFile.length() == 0L) {
                        val thumbBytes = io.omarchy.omasend.engine.ThumbnailEngine.decodeBase64(payload.thumbnail_base64)
                        if (thumbBytes != null && thumbBytes.isNotEmpty()) {
                            val tmpThumb = File(imageCacheDir, "${hash}_thumb.webp.tmp")
                            tmpThumb.writeBytes(thumbBytes)
                            tmpThumb.renameTo(thumbFile)
                            thumbFile.setLastModified(System.currentTimeMillis())
                        }
                    }
                } catch (_: Exception) {}
            }

            // 2. Lazy on-demand download if 512 KiB - 10 MiB
            if (!hasImage(hash) && client != null && peerIp.isNotBlank() && peerPort > 0) {
                scope.launch {
                    try {
                        val fetchResult = client.fetchClipboardImage(peerIp, peerPort, hash)
                        fetchResult.getOrNull()?.let { bytes ->
                            saveImageBytes(hash, bytes)
                        }
                    } catch (_: Exception) {}
                }
            }

            val displayText = payload.text.ifBlank {
                val sizeStr = payload.image_size?.let { NetworkUtils.formatBytes(it) } ?: ""
                if (sizeStr.isNotBlank()) "Görsel ($sizeStr)" else "Görsel"
            }

            return addEntry(
                text = displayText,
                senderName = payload.sender_name,
                isMine = false,
                contentType = "image",
                imageHash = hash,
                imageSize = payload.image_size,
                thumbnailBase64 = payload.thumbnail_base64,
                width = payload.width,
                height = payload.height
            )
        } else {
            return processIncomingClipboard(payload.text, payload.sender_name)
        }
    }

    suspend fun fetchAndCacheImage(
        client: io.omarchy.omasend.network.OmaSendClient,
        peerIp: String,
        peerPort: Int,
        hash: String
    ): File? {
        if (hasImage(hash)) {
            val file = getImageFile(hash)
            file.setLastModified(System.currentTimeMillis())
            return file
        }
        return try {
            val res = client.fetchClipboardImage(peerIp, peerPort, hash)
            val bytes = res.getOrNull() ?: return null
            saveImageBytes(hash, bytes)
        } catch (_: Exception) {
            null
        }
    }

    fun processLocalClipboard(context: Context, app: OmaSendApp) {
        try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? android.content.ClipboardManager ?: return
            val clip = clipboard.primaryClip ?: return
            if (clip.itemCount == 0) return
            val text = clip.getItemAt(0)?.text?.toString() ?: return
            if (text.isBlank()) return

            val hash = computeHash(text)
            if (isKnownHash(hash)) {
                return
            }

            recordHash(hash)
            val deviceName = NetworkUtils.getDeviceName(context)
            addEntry(text = text, senderName = deviceName, isMine = true, contentType = "text")

            val peers = app.discoveryManager.peers.value
            if (peers.isNotEmpty()) {
                scope.launch {
                    for (peer in peers) {
                        if (peer.transport == "BT" || peer.ip.startsWith("bt:") || peer.port <= 0) continue
                        try {
                            app.client.sendClipboard(peer.ip, peer.port, text)
                        } catch (_: Exception) {}
                    }
                }
            }
        } catch (_: Exception) {}
    }

    fun clear() {
        scope.launch {
            mutex.withLock {
                _entries.value = emptyList()
                saveEntries(emptyList())
            }
        }
    }

    private fun loadEntries() {
        scope.launch {
            mutex.withLock {
                try {
                    if (vaultFile.exists()) {
                        val content = vaultFile.readText(Charsets.UTF_8)
                        if (content.isNotBlank()) {
                            val list = json.decodeFromString(ListSerializer(ClipboardEntry.serializer()), content)
                            _entries.value = list.take(MAX_VAULT_ITEMS)
                        }
                    }
                } catch (_: Exception) {
                    _entries.value = emptyList()
                }
            }
        }
    }

    private fun saveEntries(list: List<ClipboardEntry>) {
        try {
            val content = json.encodeToString(ListSerializer(ClipboardEntry.serializer()), list)
            val tempFile = File(context.filesDir, "$VAULT_FILE_NAME.tmp")
            tempFile.writeText(content, Charsets.UTF_8)
            tempFile.renameTo(vaultFile)
        } catch (_: Exception) {
        }
    }

    companion object {
        const val VAULT_FILE_NAME = "clipboard_vault.json"
        const val MAX_VAULT_ITEMS = 20
        const val HASH_RING_CAPACITY = 64

        @Volatile
        private var INSTANCE: ClipboardVault? = null

        fun getInstance(context: Context): ClipboardVault {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: ClipboardVault(context.applicationContext).also { INSTANCE = it }
            }
        }
    }
}
