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
    }

    fun computeHash(text: String): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val hashBytes = digest.digest(text.toByteArray(Charsets.UTF_8))
            hashBytes.joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            text.hashCode().toString()
        }
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

    fun addEntry(text: String, senderName: String, isMine: Boolean): ClipboardEntry? {
        if (text.isBlank()) return null
        val entry = ClipboardEntry(
            id = UUID.randomUUID().toString(),
            text = text,
            senderName = senderName,
            timestamp = System.currentTimeMillis(),
            isMine = isMine
        )

        scope.launch {
            mutex.withLock {
                val current = _entries.value.toMutableList()
                current.removeAll { it.text == text }
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
        return addEntry(text, senderName, isMine = false)
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
            addEntry(text = text, senderName = deviceName, isMine = true)

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
