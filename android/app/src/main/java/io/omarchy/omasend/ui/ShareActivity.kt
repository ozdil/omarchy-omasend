package io.omarchy.omasend.ui

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.omarchy.omasend.OmaSendApp
import io.omarchy.omasend.model.DiscoveredPeer
import io.omarchy.omasend.model.TransferProgressState
import io.omarchy.omasend.ui.theme.OmarchyCyan
import io.omarchy.omasend.ui.theme.OmarchyDarkBg
import io.omarchy.omasend.ui.theme.OmarchyTextPrimary
import io.omarchy.omasend.ui.theme.OmarchyTextSecondary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ShareActivity : ComponentActivity() {

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val app = application as OmaSendApp
        val sharedUris = extractUrisFromIntent(intent)
        val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)

        setContent {
            io.omarchy.omasend.ui.theme.OmaSendTheme {
                val scope = rememberCoroutineScope()
                val peers by app.discoveryManager.peers.collectAsState()
                var transferState by remember { mutableStateOf<TransferProgressState>(TransferProgressState.Idle) }

                Scaffold(
                    topBar = {
                        TopAppBar(
                            title = {
                                Column {
                                    Text("Share via OmaSend", color = OmarchyCyan, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                                    Text(
                                        text = if (sharedUris.isNotEmpty()) "${sharedUris.size} file(s) selected" else "Text payload",
                                        color = OmarchyTextSecondary,
                                        fontSize = 12.sp
                                    )
                                }
                            },
                            actions = {
                                IconButton(onClick = { finish() }) {
                                    Icon(Icons.Default.Close, contentDescription = "Close", tint = OmarchyTextSecondary)
                                }
                            },
                            colors = TopAppBarDefaults.topAppBarColors(containerColor = OmarchyDarkBg)
                        )
                    },
                    containerColor = OmarchyDarkBg
                ) { padding ->
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(16.dp)
                    ) {
                        if (transferState !is TransferProgressState.Idle) {
                            TransferStatusCard(state = transferState) {
                                if (transferState is TransferProgressState.Success) {
                                    finish()
                                } else {
                                    transferState = TransferProgressState.Idle
                                }
                            }
                            Spacer(modifier = Modifier.height(16.dp))
                        }

                        Text("SELECT DESTINATION PEER", color = OmarchyCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        Spacer(modifier = Modifier.height(12.dp))

                        if (peers.isEmpty()) {
                            Column(
                                modifier = Modifier.fillMaxWidth().weight(1f),
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.Center
                            ) {
                                CircularProgressIndicator(color = OmarchyCyan)
                                Spacer(modifier = Modifier.height(12.dp))
                                Text("Looking for nearby Omarchy PCs...", color = OmarchyTextSecondary)
                            }
                        } else {
                            LazyColumn(
                                modifier = Modifier.fillMaxWidth().weight(1f),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                items(peers) { peer ->
                                    PeerCard(
                                        peer = peer,
                                        isSelected = false,
                                        onClick = {
                                            scope.launch {
                                                handleSendToPeer(app, peer, sharedUris, sharedText) { state ->
                                                    transferState = state
                                                }
                                            }
                                        },
                                        onSendFile = {
                                            scope.launch {
                                                handleSendToPeer(app, peer, sharedUris, sharedText) { state ->
                                                    transferState = state
                                                }
                                            }
                                        },
                                        onSendClipboard = {}
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private suspend fun handleSendToPeer(
        app: OmaSendApp,
        peer: DiscoveredPeer,
        uris: List<Uri>,
        text: String?,
        onState: (TransferProgressState) -> Unit
    ) {
        if (uris.isNotEmpty()) {
            for (uri in uris) {
                sendFileUriToPeer(this, app, peer, uri, onState)
            }
        } else if (!text.isNullOrEmpty()) {
            withContext(Dispatchers.IO) {
                val res = app.client.sendClipboard(peer.ip, peer.port, text)
                withContext(Dispatchers.Main) {
                    if (res.isSuccess) {
                        onState(TransferProgressState.Success("Text sent to '${peer.name}'"))
                    } else {
                        onState(TransferProgressState.Error(res.exceptionOrNull()?.message ?: "Failed to send text"))
                    }
                }
            }
        }
    }

    @Suppress("DEPRECATION")
    private fun extractUrisFromIntent(intent: Intent): List<Uri> {
        val uris = mutableListOf<Uri>()
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM)
                }
                if (uri != null) uris.add(uri)
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                val list = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
                }
                if (list != null) uris.addAll(list)
            }
        }
        return uris
    }
}
