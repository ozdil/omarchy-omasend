package io.omarchy.omasend.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AddLink
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Laptop
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.WifiTethering
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.omarchy.omasend.OmaSendApp
import io.omarchy.omasend.model.DiscoveredPeer
import io.omarchy.omasend.model.IncomingTransferPrompt
import io.omarchy.omasend.model.TransferFileInfo
import io.omarchy.omasend.model.TransferProgressState
import io.omarchy.omasend.network.NetworkUtils
import io.omarchy.omasend.network.TransferBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RadarScreen(
    app: OmaSendApp,
    incomingPrompt: IncomingTransferPrompt?,
    onAcceptPrompt: (String) -> Unit,
    onDeclinePrompt: (String) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val peers by app.discoveryManager.peers.collectAsState()

    var selectedPeer by remember { mutableStateOf<DiscoveredPeer?>(null) }
    var transferState by remember { mutableStateOf<TransferProgressState>(TransferProgressState.Idle) }
    var showSettingsDialog by remember { mutableStateOf(false) }
    var showQrDialog by remember { mutableStateOf(false) }
    var showDirectIpDialog by remember { mutableStateOf(false) }

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null && selectedPeer != null) {
            val peer = selectedPeer!!
            scope.launch {
                sendFileUriToPeer(context, app, peer, uri) { state ->
                    transferState = state
                }
            }
        }
    }

    val bluetoothFilePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetMultipleContents()
    ) { uris ->
        if (uris.isNotEmpty()) {
            TransferBridge.sendViaBluetooth(context, uris)
        }
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "OmaSend",
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.titleLarge,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = MaterialTheme.colorScheme.secondaryContainer
                        ) {
                            Text(
                                text = "AirBridge",
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSecondaryContainer
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = { showQrDialog = true }) {
                        Icon(
                            Icons.Default.QrCode,
                            contentDescription = "QR / Barkod",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(onClick = { showDirectIpDialog = true }) {
                        Icon(
                            Icons.Default.AddLink,
                            contentDescription = "Doğrudan IP",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(onClick = {
                        app.discoveryManager.stop()
                        app.discoveryManager.start()
                        Toast.makeText(context, "Scanning local network...", Toast.LENGTH_SHORT).show()
                    }) {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = "Scan",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(onClick = { showSettingsDialog = true }) {
                        Icon(
                            Icons.Default.Settings,
                            contentDescription = "Settings",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        containerColor = MaterialTheme.colorScheme.background
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp, vertical = 8.dp)
        ) {
            // Local Device Status Banner
            LocalDeviceHeroCard(context = context)

            Spacer(modifier = Modifier.height(14.dp))

            // Active Transfer Status Indicator
            AnimatedVisibility(visible = transferState !is TransferProgressState.Idle) {
                Column {
                    TransferStatusCard(
                        state = transferState,
                        onDismiss = { transferState = TransferProgressState.Idle }
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                }
            }

            // Radar Scan Header with Badge
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "NEARBY PEERS",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary,
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Surface(
                        shape = CircleShape,
                        color = if (peers.isNotEmpty()) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant
                    ) {
                        Text(
                            text = "${peers.size}",
                            modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = if (peers.isNotEmpty()) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                PulseBeaconIndicator()
            }

            Spacer(modifier = Modifier.height(10.dp))

            if (peers.isEmpty()) {
                ModernRadarEmptyState(modifier = Modifier.weight(1f))
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(peers, key = { it.id }) { peer ->
                        val isSelected = selectedPeer?.id == peer.id
                        PeerCard(
                            peer = peer,
                            isSelected = isSelected,
                            onClick = { selectedPeer = if (isSelected) null else peer },
                            onSendFile = {
                                selectedPeer = peer
                                filePickerLauncher.launch("*/*")
                            },
                            onSendClipboard = {
                                selectedPeer = peer
                                scope.launch {
                                    sendClipboardToPeer(context, app, peer) { state ->
                                        transferState = state
                                    }
                                }
                            }
                        )
                    }
                }
            }

            // Selected Peer Quick Actions Sheet
            AnimatedVisibility(visible = selectedPeer != null) {
                selectedPeer?.let { peer ->
                    ElevatedCard(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.elevatedCardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
                        )
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "Send to ${peer.name}",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                TextButton(onClick = { selectedPeer = null }) {
                                    Text("Close", color = MaterialTheme.colorScheme.primary)
                                }
                            }
                            Spacer(modifier = Modifier.height(10.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Button(
                                    onClick = { filePickerLauncher.launch("*/*") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(14.dp)
                                ) {
                                    Icon(
                                        Icons.Default.Folder,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Send File", fontWeight = FontWeight.SemiBold)
                                }
                                FilledTonalButton(
                                    onClick = {
                                        scope.launch {
                                            sendClipboardToPeer(context, app, peer) { state ->
                                                transferState = state
                                            }
                                        }
                                    },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(14.dp)
                                ) {
                                    Icon(
                                        Icons.Default.ContentCopy,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Clipboard", fontWeight = FontWeight.SemiBold)
                                }
                            }
                        }
                    }
                }
            }

            // Alternative Transfer Channels Row (Bluetooth, QR Code, Direct IP)
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surfaceContainer,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 4.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextButton(
                        onClick = { bluetoothFilePicker.launch("*/*") }
                    ) {
                        Icon(
                            Icons.Default.Bluetooth,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Bluetooth",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }

                    TextButton(
                        onClick = { showQrDialog = true }
                    ) {
                        Icon(
                            Icons.Default.QrCode,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "QR / Barkod",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }

                    TextButton(
                        onClick = { showDirectIpDialog = true }
                    ) {
                        Icon(
                            Icons.Default.AddLink,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Manuel IP",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }

        // Incoming Transfer Consent Dialog
        if (incomingPrompt != null) {
            AlertDialog(
                onDismissRequest = { onDeclinePrompt(incomingPrompt.token) },
                shape = RoundedCornerShape(28.dp),
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                icon = {
                    Surface(
                        shape = CircleShape,
                        color = MaterialTheme.colorScheme.primaryContainer,
                        modifier = Modifier.size(48.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                Icons.Default.PhoneAndroid,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onPrimaryContainer,
                                modifier = Modifier.size(24.dp)
                            )
                        }
                    }
                },
                title = {
                    Text(
                        text = "Incoming Transfer",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                },
                text = {
                    Column {
                        Text(
                            text = "${incomingPrompt.senderName} wants to share files with you:",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        Surface(
                            shape = RoundedCornerShape(16.dp),
                            color = MaterialTheme.colorScheme.surfaceContainer,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                incomingPrompt.files.forEach { file ->
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.padding(vertical = 2.dp)
                                    ) {
                                        Icon(
                                            Icons.Default.Folder,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.primary,
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = file.name,
                                            style = MaterialTheme.typography.bodySmall,
                                            fontWeight = FontWeight.Medium,
                                            color = MaterialTheme.colorScheme.onSurface
                                        )
                                        Spacer(modifier = Modifier.weight(1f))
                                        Text(
                                            text = NetworkUtils.formatBytes(file.size_bytes),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Total Payload: ${NetworkUtils.formatBytes(incomingPrompt.totalSizeBytes)}",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = { onAcceptPrompt(incomingPrompt.token) },
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Accept", fontWeight = FontWeight.Bold)
                    }
                },
                dismissButton = {
                    OutlinedButton(
                        onClick = { onDeclinePrompt(incomingPrompt.token) },
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Decline", color = MaterialTheme.colorScheme.error)
                    }
                }
            )
        }

        // Settings Dialog
        if (showSettingsDialog) {
            var newName by remember { mutableStateOf(NetworkUtils.getDeviceName(context)) }
            AlertDialog(
                onDismissRequest = { showSettingsDialog = false },
                shape = RoundedCornerShape(28.dp),
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                title = {
                    Text(
                        text = "Device Settings",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                },
                text = {
                    Column {
                        Text(
                            text = "Device Name (visible to nearby peers):",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(
                            value = newName,
                            onValueChange = { newName = it },
                            singleLine = true,
                            shape = RoundedCornerShape(14.dp),
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            NetworkUtils.setDeviceName(context, newName)
                            showSettingsDialog = false
                        },
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Save")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showSettingsDialog = false }) {
                        Text("Cancel")
                    }
                }
            )
        }

        if (showQrDialog) {
            QrCodeDialog(
                onDismiss = { showQrDialog = false },
                onConnectEndpoint = { endpoint ->
                    val parsed = TransferBridge.parseConnectionEndpoint(endpoint)
                    if (parsed != null) {
                        app.discoveryManager.addManualPeer(parsed.first, parsed.second)
                        Toast.makeText(context, "Cihaz eklendi: ${parsed.first}", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(context, "Girdi geçersiz IPv4 veya endpoint", Toast.LENGTH_SHORT).show()
                    }
                }
            )
        }

        if (showDirectIpDialog) {
            DirectIpDialog(
                onDismiss = { showDirectIpDialog = false },
                onConnect = { ip, port ->
                    app.discoveryManager.addManualPeer(ip, port)
                    Toast.makeText(context, "Doğrudan bağlantı eklendi: $ip:$port", Toast.LENGTH_SHORT).show()
                }
            )
        }
    }
}


@Composable
fun LocalDeviceHeroCard(context: Context) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.primaryContainer,
                modifier = Modifier.size(46.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        Icons.Default.PhoneAndroid,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.size(24.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = NetworkUtils.getDeviceName(context),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = "${NetworkUtils.getLocalIpAddress()}:53317",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontFamily = FontFamily.Monospace
                )
            }

            Surface(
                shape = RoundedCornerShape(10.dp),
                color = MaterialTheme.colorScheme.secondaryContainer
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Wifi,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.size(12.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "Active",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                }
            }
        }
    }
}

@Composable
fun PeerCard(
    peer: DiscoveredPeer,
    isSelected: Boolean,
    onClick: () -> Unit,
    onSendFile: () -> Unit,
    onSendClipboard: () -> Unit
) {
    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = if (isSelected) {
                MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f)
            } else {
                MaterialTheme.colorScheme.surfaceContainer
            }
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondaryContainer,
                modifier = Modifier.size(44.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    val icon = if (peer.name.lowercase().contains("phone") || peer.name.lowercase().contains("android")) {
                        Icons.Default.PhoneAndroid
                    } else if (peer.name.lowercase().contains("laptop") || peer.name.lowercase().contains("thinkpad")) {
                        Icons.Default.Laptop
                    } else {
                        Icons.Default.Computer
                    }
                    Icon(
                        icon,
                        contentDescription = null,
                        tint = if (isSelected) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.size(22.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = peer.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = "${peer.ip}:${peer.port} • ${peer.transport}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontFamily = FontFamily.Monospace
                )
            }

            FilledTonalIconButton(onClick = onSendClipboard) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = "Sync Clipboard",
                    modifier = Modifier.size(18.dp)
                )
            }
            Spacer(modifier = Modifier.width(6.dp))
            FilledTonalIconButton(onClick = onSendFile) {
                Icon(
                    Icons.AutoMirrored.Filled.Send,
                    contentDescription = "Send File",
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    }
}

@Composable
fun ModernRadarEmptyState(modifier: Modifier = Modifier) {
    val infiniteTransition = rememberInfiniteTransition(label = "radarWaves")
    val wave1 by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "wave1"
    )
    val wave2 by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2400, delayMillis = 1200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "wave2"
    )

    val primaryColor = MaterialTheme.colorScheme.primary

    ElevatedCard(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp)),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Canvas(modifier = Modifier.size(240.dp)) {
                val maxRadius = size.minDimension / 2f
                // Inner ring
                drawCircle(
                    color = primaryColor.copy(alpha = 0.12f),
                    radius = maxRadius * 0.35f
                )
                // Wave 1
                drawCircle(
                    color = primaryColor.copy(alpha = (1f - wave1) * 0.3f),
                    radius = maxRadius * wave1,
                    style = Stroke(width = 2.dp.toPx())
                )
                // Wave 2
                drawCircle(
                    color = primaryColor.copy(alpha = (1f - wave2) * 0.3f),
                    radius = maxRadius * wave2,
                    style = Stroke(width = 2.dp.toPx())
                )
            }

            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.padding(24.dp)
            ) {
                Surface(
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.size(54.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            Icons.Default.WifiTethering,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.size(28.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "Scanning Wi-Fi on port 53317",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Open OmaSend on your PC or other Android devices",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun TransferStatusCard(
    state: TransferProgressState,
    onDismiss: () -> Unit
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            when (state) {
                is TransferProgressState.Requesting -> {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = MaterialTheme.colorScheme.primary,
                            strokeWidth = 2.5.dp
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "Requesting transfer to '${state.peerName}'...",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
                is TransferProgressState.WaitingConsent -> {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = MaterialTheme.colorScheme.primary,
                            strokeWidth = 2.5.dp
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "Waiting for '${state.peerName}' to accept...",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
                is TransferProgressState.Transferring -> {
                    Text(
                        text = if (state.isUploading) "Uploading to '${state.peerName}'" else "Receiving from '${state.peerName}'",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "${state.fileName} (${NetworkUtils.formatBytes(state.bytesTransferred)} / ${NetworkUtils.formatBytes(state.totalBytes)})",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontFamily = FontFamily.Monospace
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    LinearProgressIndicator(
                        progress = { state.percent / 100f },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(8.dp)
                            .clip(RoundedCornerShape(4.dp)),
                        color = MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                }
                is TransferProgressState.Success -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = state.message,
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                        TextButton(onClick = onDismiss) {
                            Text("OK", color = MaterialTheme.colorScheme.primary)
                        }
                    }
                }
                is TransferProgressState.Error -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Default.Error,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = state.message,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                        TextButton(onClick = onDismiss) {
                            Text("Dismiss", color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
                else -> {}
            }
        }
    }
}

@Composable
fun PulseBeaconIndicator() {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val scale by infiniteTransition.animateFloat(
        initialValue = 0.8f,
        targetValue = 1.3f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )

    val color = MaterialTheme.colorScheme.primary

    Box(
        modifier = Modifier
            .size(10.dp)
            .scale(scale)
            .clip(CircleShape)
            .background(color)
    )
}

suspend fun sendFileUriToPeer(
    context: Context,
    app: OmaSendApp,
    peer: DiscoveredPeer,
    uri: Uri,
    onState: (TransferProgressState) -> Unit
) {
    withContext(Dispatchers.IO) {
        try {
            var fileName = "file"
            var fileSize = 0L

            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (cursor.moveToFirst()) {
                    if (nameIndex != -1) fileName = cursor.getString(nameIndex) ?: "file"
                    if (sizeIndex != -1) fileSize = cursor.getLong(sizeIndex)
                }
            }

            if (fileSize <= 0) {
                fileSize = context.contentResolver.openInputStream(uri)?.use { it.available().toLong() } ?: 0L
            }

            withContext(Dispatchers.Main) {
                onState(TransferProgressState.Requesting(peer.name, fileName))
            }

            val fileInfo = TransferFileInfo(fileName, fileSize)
            val requestResult = app.client.sendTransferRequest(peer.ip, peer.port, listOf(fileInfo))

            val token = requestResult.getOrElse {
                withContext(Dispatchers.Main) {
                    onState(TransferProgressState.Error(it.message ?: "Transfer request failed"))
                }
                return@withContext
            }

            withContext(Dispatchers.Main) {
                onState(TransferProgressState.WaitingConsent(peer.name))
            }

            val decisionResult = app.client.pollDecision(peer.ip, peer.port, token)
            if (decisionResult.isFailure) {
                withContext(Dispatchers.Main) {
                    onState(TransferProgressState.Error(decisionResult.exceptionOrNull()?.message ?: "Transfer rejected"))
                }
                return@withContext
            }

            val inputStream = context.contentResolver.openInputStream(uri) ?: throw Exception("Failed to open file stream")

            withContext(Dispatchers.Main) {
                onState(TransferProgressState.Transferring(true, peer.name, fileName, 0, fileSize, 0))
            }

            val uploadResult = app.client.uploadFileStream(
                targetIp = peer.ip,
                targetPort = peer.port,
                token = token,
                filename = fileName,
                totalBytes = fileSize,
                inputStream = inputStream
            ) { bytes, total, pct ->
                scopeLaunchMain {
                    onState(TransferProgressState.Transferring(true, peer.name, fileName, bytes, total, pct))
                }
            }

            withContext(Dispatchers.Main) {
                if (uploadResult.isSuccess) {
                    onState(TransferProgressState.Success("Sent '$fileName' successfully!"))
                } else {
                    onState(TransferProgressState.Error(uploadResult.exceptionOrNull()?.message ?: "Upload failed"))
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                onState(TransferProgressState.Error(e.message ?: "Transfer error"))
            }
        }
    }
}

suspend fun sendClipboardToPeer(
    context: Context,
    app: OmaSendApp,
    peer: DiscoveredPeer,
    onState: (TransferProgressState) -> Unit
) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    val clip = clipboard?.primaryClip
    val text = if (clip != null && clip.itemCount > 0) clip.getItemAt(0).text?.toString() else null

    if (text.isNullOrEmpty()) {
        withContext(Dispatchers.Main) {
            Toast.makeText(context, "Clipboard is empty. Copy text first.", Toast.LENGTH_SHORT).show()
        }
        return
    }

    withContext(Dispatchers.IO) {
        val res = app.client.sendClipboard(peer.ip, peer.port, text)
        withContext(Dispatchers.Main) {
            if (res.isSuccess) {
                onState(TransferProgressState.Success("Clipboard synced to '${peer.name}'"))
            } else {
                onState(TransferProgressState.Error(res.exceptionOrNull()?.message ?: "Clipboard sync failed"))
            }
        }
    }
}

private fun scopeLaunchMain(block: () -> Unit) {
    android.os.Handler(android.os.Looper.getMainLooper()).post(block)
}

@Composable
fun QrCodeDialog(
    onDismiss: () -> Unit,
    onConnectEndpoint: (String) -> Unit
) {
    val context = LocalContext.current
    val myIp = NetworkUtils.getLocalIpAddress()
    val endpointUrl = "http://$myIp:${NetworkUtils.PORT}"
    val qrBitmap = remember(endpointUrl) {
        TransferBridge.generateQrCode(endpointUrl, 512)
    }
    var manualInput by remember { mutableStateOf("") }
    var inputError by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(28.dp),
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.QrCode,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = "QR / Barkod ile Bağlan",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        },
        text = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Aynı ağdaki başka bir telefon veya PC tarayıcısından bu kodu okutarak bağlanabilir:",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(14.dp))

                // White surface container for high-contrast QR scannability in all themes
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = Color.White,
                    modifier = Modifier.size(200.dp)
                ) {
                    Box(contentAlignment = Alignment.Center, modifier = Modifier.padding(12.dp)) {
                        if (qrBitmap != null) {
                            Image(
                                bitmap = qrBitmap.asImageBitmap(),
                                contentDescription = "OmaSend Connection QR Code",
                                modifier = Modifier.fillMaxSize()
                            )
                        } else {
                            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceContainer,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = endpointUrl,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        IconButton(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                                clipboard?.setPrimaryClip(ClipData.newPlainText("OmaSend Endpoint", endpointUrl))
                                Toast.makeText(context, "URL panoya kopyalandı", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                Icons.Default.ContentCopy,
                                contentDescription = "Copy",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "Veya taranan QR metnini / IP adresini girin:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.align(Alignment.Start)
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = manualInput,
                    onValueChange = {
                        manualInput = it
                        inputError = null
                    },
                    placeholder = { Text("Örn: 192.168.1.50:53317", fontSize = 13.sp) },
                    singleLine = true,
                    isError = inputError != null,
                    supportingText = inputError?.let { { Text(it, color = MaterialTheme.colorScheme.error) } },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (manualInput.isNotBlank()) {
                        val endpoint = TransferBridge.parseConnectionEndpoint(manualInput)
                        if (endpoint != null) {
                            onConnectEndpoint(manualInput)
                            onDismiss()
                        } else {
                            inputError = "Geçersiz IP adresi veya format (IPv4 zorunlu)"
                        }
                    } else {
                        onDismiss()
                    }
                },
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(if (manualInput.isNotBlank()) "Bağlan" else "Tamam")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Kapat")
            }
        }
    )
}

@Composable
fun DirectIpDialog(
    onDismiss: () -> Unit,
    onConnect: (String, Int) -> Unit
) {
    var ipText by remember { mutableStateOf("") }
    var portText by remember { mutableStateOf("53317") }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(28.dp),
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.AddLink,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = "Doğrudan IP ile Bağlan",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        },
        text = {
            Column {
                Text(
                    text = "UDP yayın paketlerini engelleyen kısıtlı veya misafir ağlarında cihazın IP adresini girerek doğrudan bağlanabilirsiniz.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(14.dp))
                OutlinedTextField(
                    value = ipText,
                    onValueChange = {
                        ipText = it
                        errorMessage = null
                    },
                    label = { Text("Hedef IP Adresi") },
                    placeholder = { Text("192.168.1.50") },
                    singleLine = true,
                    isError = errorMessage != null,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
                Spacer(modifier = Modifier.height(10.dp))
                OutlinedTextField(
                    value = portText,
                    onValueChange = { portText = it },
                    label = { Text("Port") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
                if (errorMessage != null) {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = errorMessage!!,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val trimmedIp = ipText.trim()
                    val port = portText.trim().toIntOrNull() ?: 53317
                    if (!TransferBridge.isValidIpv4(trimmedIp)) {
                        errorMessage = "Lütfen geçerli bir IPv4 adresi girin (örn: 192.168.1.50)"
                        return@Button
                    }
                    if (port !in 1024..65535) {
                        errorMessage = "Port numarası 1024 ile 65535 arasında olmalıdır"
                        return@Button
                    }
                    onConnect(trimmedIp, port)
                    onDismiss()
                },
                shape = RoundedCornerShape(12.dp)
            ) {
                Text("Cihazı Ekle")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("İptal")
            }
        }
    )
}

