package io.omarchy.omasend.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import io.omarchy.omasend.OmaSendApp
import io.omarchy.omasend.model.*
import io.omarchy.omasend.network.NetworkUtils
import io.omarchy.omasend.network.TransferBridge
import io.omarchy.omasend.service.OmaSendForegroundService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

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
    val discoveryMode by app.discoveryManager.discoveryMode.collectAsState()

    var selectedPeer by remember { mutableStateOf<DiscoveredPeer?>(null) }
    var transferState by remember { mutableStateOf<TransferProgressState>(TransferProgressState.Idle) }

    var showInfoDialog by remember { mutableStateOf(false) }
    var showQrDialog by remember { mutableStateOf(false) }
    var showDirectIpDialog by remember { mutableStateOf(false) }
    var showRenameDialog by remember { mutableStateOf(false) }
    var showTargetSelectorDialog by remember { mutableStateOf(false) }
    var pendingUrisToSend by remember { mutableStateOf<List<Uri>>(emptyList()) }

    var recentFiles by remember { mutableStateOf<List<File>>(emptyList()) }
    var isRefreshing by remember { mutableStateOf(false) }

    fun refreshRecentFiles() {
        recentFiles = getRecentReceivedFiles()
    }

    LaunchedEffect(Unit) {
        refreshRecentFiles()
    }

    // Refresh animation
    val refreshRotation = remember { Animatable(0f) }

    // Multi-file picker (Documents / Any file)
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetMultipleContents()
    ) { uris ->
        if (uris.isNotEmpty()) {
            if (selectedPeer != null) {
                scope.launch {
                    sendMultipleUrisToPeer(context, app, selectedPeer!!, uris) { state ->
                        transferState = state
                        if (state is TransferProgressState.Success) refreshRecentFiles()
                    }
                }
            } else {
                pendingUrisToSend = uris
                showTargetDeviceSheetOrFallback(peers, onSelectTarget = { peer ->
                    selectedPeer = peer
                    scope.launch {
                        sendMultipleUrisToPeer(context, app, peer, uris) { state ->
                            transferState = state
                            if (state is TransferProgressState.Success) refreshRecentFiles()
                        }
                    }
                }, onNoTarget = {
                    showTargetSelectorDialog = true
                })
            }
        }
    }

    // Media Picker (Images & Videos)
    val mediaPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickMultipleVisualMedia()
    ) { uris ->
        if (uris.isNotEmpty()) {
            if (selectedPeer != null) {
                scope.launch {
                    sendMultipleUrisToPeer(context, app, selectedPeer!!, uris) { state ->
                        transferState = state
                        if (state is TransferProgressState.Success) refreshRecentFiles()
                    }
                }
            } else {
                pendingUrisToSend = uris
                showTargetDeviceSheetOrFallback(peers, onSelectTarget = { peer ->
                    selectedPeer = peer
                    scope.launch {
                        sendMultipleUrisToPeer(context, app, peer, uris) { state ->
                            transferState = state
                            if (state is TransferProgressState.Success) refreshRecentFiles()
                        }
                    }
                }, onNoTarget = {
                    showTargetSelectorDialog = true
                })
            }
        }
    }

    // Direct single file picker for specific peer click
    val singlePeerFilePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetMultipleContents()
    ) { uris ->
        if (uris.isNotEmpty() && selectedPeer != null) {
            val peer = selectedPeer!!
            scope.launch {
                sendMultipleUrisToPeer(context, app, peer, uris) { state ->
                    transferState = state
                    if (state is TransferProgressState.Success) refreshRecentFiles()
                }
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(
                            shape = CircleShape,
                            color = MaterialTheme.colorScheme.primaryContainer,
                            modifier = Modifier.size(36.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    Icons.Default.Send,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            text = "OmaSend",
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.titleLarge,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = if (discoveryMode != DiscoveryMode.OFF) MaterialTheme.colorScheme.primary.copy(alpha = 0.15f) else MaterialTheme.colorScheme.surfaceVariant
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(6.dp)
                                        .clip(CircleShape)
                                        .background(if (discoveryMode != DiscoveryMode.OFF) Color(0xFF10B981) else Color.Gray)
                                )
                                Spacer(modifier = Modifier.width(5.dp))
                                Text(
                                    text = if (discoveryMode != DiscoveryMode.OFF) "Çevrimiçi" else "Duraklatıldı",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = if (discoveryMode != DiscoveryMode.OFF) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            }
                        }
                    }
                },
                actions = {
                    IconButton(
                        onClick = {
                            scope.launch {
                                isRefreshing = true
                                refreshRotation.animateTo(
                                    targetValue = refreshRotation.value + 360f,
                                    animationSpec = tween(600, easing = FastOutSlowInEasing)
                                )
                                app.discoveryManager.refreshBluetoothPeers()
                                refreshRecentFiles()
                                isRefreshing = false
                                Toast.makeText(context, "Ağ ve Bluetooth eşleri güncellendi", Toast.LENGTH_SHORT).show()
                            }
                        },
                        modifier = Modifier.size(38.dp)
                    ) {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = "Yenile",
                            modifier = Modifier.rotate(refreshRotation.value).size(20.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(
                        onClick = { showQrDialog = true },
                        modifier = Modifier.size(38.dp)
                    ) {
                        Icon(
                            Icons.Default.QrCode,
                            contentDescription = "Web QR Paylaşım",
                            modifier = Modifier.size(20.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(
                        onClick = { showDirectIpDialog = true },
                        modifier = Modifier.size(38.dp)
                    ) {
                        Icon(
                            Icons.Default.AddLink,
                            contentDescription = "Doğrudan IP Ekle",
                            modifier = Modifier.size(20.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(
                        onClick = { showInfoDialog = true },
                        modifier = Modifier.size(38.dp)
                    ) {
                        Icon(
                            Icons.Default.Info,
                            contentDescription = "Bilgi",
                            modifier = Modifier.size(20.dp),
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
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
            contentPadding = PaddingValues(vertical = 12.dp)
        ) {
            // 1. Cihazım ve Görünürlük Kartı
            item {
                LocalDeviceHeroCard(
                    context = context,
                    currentMode = discoveryMode,
                    onModeSelected = { newMode ->
                        app.discoveryManager.setMode(newMode)
                        if (newMode == DiscoveryMode.OFF) {
                            OmaSendForegroundService.stopService(context)
                            Toast.makeText(context, "Görünürlük kapatıldı", Toast.LENGTH_SHORT).show()
                        } else {
                            OmaSendForegroundService.startService(context)
                            val msg = if (newMode == DiscoveryMode.KNOWN_PEERS) {
                                "Yalnızca bilinen ve eşleşmiş cihazlar taranıyor"
                            } else {
                                "Görünürlük: Herkese Açık (10 dk)"
                            }
                            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                        }
                    },
                    onRename = { showRenameDialog = true }
                )
            }

            // 2. Hızlı Gönderim Butonları (Kullanımı Kolaylaştıran Hub)
            item {
                QuickSendHubCard(
                    onPickFiles = { filePickerLauncher.launch("*/*") },
                    onPickMedia = {
                        mediaPickerLauncher.launch(
                            PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo)
                        )
                    },
                    onSendClipboard = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        val clipText = clipboard?.primaryClip?.let {
                            if (it.itemCount > 0) it.getItemAt(0).text?.toString() else null
                        }
                        if (clipText.isNullOrEmpty()) {
                            Toast.makeText(context, "Telefon panosu boş!", Toast.LENGTH_SHORT).show()
                        } else if (peers.isEmpty()) {
                            Toast.makeText(context, "Panoyu gönderecek yakında cihaz bulunamadı", Toast.LENGTH_SHORT).show()
                        } else {
                            val target = selectedPeer ?: peers.first()
                            scope.launch {
                                sendClipboardToPeer(context, app, target) { state ->
                                    transferState = state
                                }
                            }
                        }
                    },
                    onShowWebPortal = { showQrDialog = true }
                )
            }

            // 3. Aktif Transfer Durum Bildirimi
            if (transferState !is TransferProgressState.Idle) {
                item {
                    TransferStatusCard(
                        state = transferState,
                        onDismiss = { transferState = TransferProgressState.Idle }
                    )
                }
            }

            // 4. Yakındaki ve Eşleşmiş Cihazlar Listesi
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 4.dp, vertical = 2.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "YAKINDAKİ CİHAZLAR",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary,
                            letterSpacing = 0.8.sp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Surface(
                            shape = CircleShape,
                            color = if (peers.isNotEmpty()) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant
                        ) {
                            Text(
                                text = "${peers.size}",
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = if (peers.isNotEmpty()) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            if (peers.isEmpty()) {
                item {
                    CleanEmptyStateCard(
                        isOff = discoveryMode == DiscoveryMode.OFF,
                        onEnableScan = {
                            app.discoveryManager.setMode(DiscoveryMode.EVERYONE)
                            OmaSendForegroundService.startService(context)
                        },
                        onAddDirectIp = { showDirectIpDialog = true }
                    )
                }
            } else {
                items(peers, key = { it.id }) { peer ->
                    ModernPeerCard(
                        peer = peer,
                        isSelected = selectedPeer?.id == peer.id,
                        onCardClick = {
                            selectedPeer = if (selectedPeer?.id == peer.id) null else peer
                        },
                        onSendClick = {
                            selectedPeer = peer
                            singlePeerFilePicker.launch("*/*")
                        },
                        onClipboardClick = {
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

            // 5. Son Alınan Dosyalar (Ekstra Kolaylık Özelliği)
            if (recentFiles.isNotEmpty()) {
                item {
                    RecentReceivedFilesCard(
                        files = recentFiles,
                        onOpenFile = { file -> openFileWithSystem(context, file) },
                        onShareFile = { file -> shareFileWithSystem(context, file) }
                    )
                }
            }
        }
    }

    // Dialogs
    if (showRenameDialog) {
        RenameDeviceDialog(
            currentName = NetworkUtils.getDeviceName(context),
            onDismiss = { showRenameDialog = false },
            onConfirm = { newName ->
                NetworkUtils.setDeviceName(context, newName)
                showRenameDialog = false
                Toast.makeText(context, "Cihaz adı güncellendi: $newName", Toast.LENGTH_SHORT).show()
            }
        )
    }

    if (showQrDialog) {
        QrCodeDialog(
            context = context,
            onDismiss = { showQrDialog = false }
        )
    }

    if (showDirectIpDialog) {
        DirectIpDialog(
            onDismiss = { showDirectIpDialog = false },
            onConnect = { ip, port ->
                app.discoveryManager.addManualPeer(ip, port)
                showDirectIpDialog = false
                Toast.makeText(context, "$ip:$port eklendi", Toast.LENGTH_SHORT).show()
            }
        )
    }

    if (showInfoDialog) {
        InfoDialog(onDismiss = { showInfoDialog = false })
    }

    if (showTargetSelectorDialog) {
        TargetDeviceSelectionDialog(
            peers = peers,
            onDismiss = { showTargetSelectorDialog = false },
            onSelect = { peer ->
                showTargetSelectorDialog = false
                selectedPeer = peer
                if (pendingUrisToSend.isNotEmpty()) {
                    scope.launch {
                        sendMultipleUrisToPeer(context, app, peer, pendingUrisToSend) { state ->
                            transferState = state
                            if (state is TransferProgressState.Success) refreshRecentFiles()
                        }
                        pendingUrisToSend = emptyList()
                    }
                }
            }
        )
    }

    // Gelen Transfer İstemi
    if (incomingPrompt != null) {
        IncomingTransferDialog(
            prompt = incomingPrompt,
            onAccept = { onAcceptPrompt(incomingPrompt.token) },
            onDecline = { onDeclinePrompt(incomingPrompt.token) }
        )
    }
}

private fun showTargetDeviceSheetOrFallback(
    peers: List<DiscoveredPeer>,
    onSelectTarget: (DiscoveredPeer) -> Unit,
    onNoTarget: () -> Unit
) {
    if (peers.size == 1) {
        onSelectTarget(peers.first())
    } else {
        onNoTarget()
    }
}

// ------------------- UI BİLEŞENLERİ (MATERIAL 3) -------------------

@Composable
fun LocalDeviceHeroCard(
    context: Context,
    currentMode: DiscoveryMode,
    onModeSelected: (DiscoveryMode) -> Unit,
    onRename: () -> Unit
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.size(48.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            Icons.Default.PhoneAndroid,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(26.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.width(14.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = NetworkUtils.getDeviceName(context),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        IconButton(
                            onClick = onRename,
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                Icons.Default.Edit,
                                contentDescription = "Adı Değiştir",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "IP: ${NetworkUtils.getLocalIpAddress()}:53317 • BT Aktif",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
            Spacer(modifier = Modifier.height(12.dp))

            // Visibility Segmented Options
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        color = MaterialTheme.colorScheme.surfaceContainerHigh,
                        shape = RoundedCornerShape(12.dp)
                    )
                    .padding(3.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                listOf(
                    Triple(DiscoveryMode.EVERYONE, "Herkes", Icons.Default.Public),
                    Triple(DiscoveryMode.KNOWN_PEERS, "Bilinenler", Icons.Default.Group),
                    Triple(DiscoveryMode.OFF, "Kapalı", Icons.Default.Lock)
                ).forEach { (mode, label, icon) ->
                    val isSelected = currentMode == mode
                    Surface(
                        onClick = { onModeSelected(mode) },
                        shape = RoundedCornerShape(9.dp),
                        color = if (isSelected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent,
                        modifier = Modifier
                            .weight(1f)
                            .height(36.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(horizontal = 4.dp),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                icon,
                                contentDescription = null,
                                modifier = Modifier.size(15.dp),
                                tint = if (isSelected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.width(5.dp))
                            Text(
                                text = label,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                color = if (isSelected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                softWrap = false
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun QuickSendHubCard(
    onPickFiles: () -> Unit,
    onPickMedia: () -> Unit,
    onSendClipboard: () -> Unit,
    onShowWebPortal: () -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "HIZLI GÖNDERİM",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary,
            letterSpacing = 0.8.sp,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
        )
        Spacer(modifier = Modifier.height(8.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            QuickActionItem(
                title = "Dosyalar",
                icon = Icons.Default.Folder,
                modifier = Modifier.weight(1f),
                onClick = onPickFiles
            )
            QuickActionItem(
                title = "Galeri",
                icon = Icons.Default.Image,
                modifier = Modifier.weight(1f),
                onClick = onPickMedia
            )
            QuickActionItem(
                title = "Pano",
                icon = Icons.Default.ContentCopy,
                modifier = Modifier.weight(1f),
                onClick = onSendClipboard
            )
            QuickActionItem(
                title = "Web Portal",
                icon = Icons.Default.QrCode,
                modifier = Modifier.weight(1f),
                onClick = onShowWebPortal
            )
        }
    }
}

@Composable
fun QuickActionItem(
    title: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = modifier.height(82.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                icon,
                contentDescription = title,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = title,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
fun ModernPeerCard(
    peer: DiscoveredPeer,
    isSelected: Boolean,
    onCardClick: () -> Unit,
    onSendClick: () -> Unit,
    onClipboardClick: () -> Unit
) {
    ElevatedCard(
        onClick = onCardClick,
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = if (isSelected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f) else MaterialTheme.colorScheme.surfaceContainer
        ),
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (isSelected) Modifier.border(1.5.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(18.dp))
                else Modifier
            )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(
                shape = CircleShape,
                color = when (peer.transport) {
                    "BT" -> MaterialTheme.colorScheme.tertiaryContainer
                    "HYBRID" -> MaterialTheme.colorScheme.secondaryContainer
                    else -> MaterialTheme.colorScheme.primaryContainer
                },
                modifier = Modifier.size(46.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    val icon = if (peer.transport == "BT") {
                        Icons.Default.Bluetooth
                    } else if (peer.name.lowercase().contains("phone") || peer.name.lowercase().contains("android")) {
                        Icons.Default.PhoneAndroid
                    } else if (peer.name.lowercase().contains("laptop") || peer.name.lowercase().contains("thinkpad")) {
                        Icons.Default.Laptop
                    } else {
                        Icons.Default.Computer
                    }
                    Icon(
                        icon,
                        contentDescription = null,
                        tint = when (peer.transport) {
                            "BT" -> MaterialTheme.colorScheme.onTertiaryContainer
                            "HYBRID" -> MaterialTheme.colorScheme.onSecondaryContainer
                            else -> MaterialTheme.colorScheme.onPrimaryContainer
                        },
                        modifier = Modifier.size(24.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = peer.name,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Spacer(modifier = Modifier.height(2.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = when (peer.transport) {
                            "BT" -> MaterialTheme.colorScheme.tertiary.copy(alpha = 0.15f)
                            "HYBRID" -> MaterialTheme.colorScheme.secondary.copy(alpha = 0.15f)
                            else -> MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)
                        }
                    ) {
                        Text(
                            text = peer.transport,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = when (peer.transport) {
                                "BT" -> MaterialTheme.colorScheme.tertiary
                                "HYBRID" -> MaterialTheme.colorScheme.secondary
                                else -> MaterialTheme.colorScheme.primary
                            }
                        )
                    }
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (peer.ip.startsWith("bt:")) "Bluetooth Paired" else "${peer.ip}:${peer.port}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Action Buttons
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (!peer.ip.startsWith("bt:")) {
                    IconButton(
                        onClick = onClipboardClick,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            Icons.Default.ContentCopy,
                            contentDescription = "Pano Gönder",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(4.dp))
                }

                FilledTonalButton(
                    onClick = onSendClick,
                    shape = RoundedCornerShape(12.dp),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)
                ) {
                    Icon(
                        Icons.Default.Send,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "GÖNDER",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Composable
fun CleanEmptyStateCard(
    isOff: Boolean,
    onEnableScan: () -> Unit,
    onAddDirectIp: () -> Unit
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.surfaceContainerHigh,
                modifier = Modifier.size(72.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        if (isOff) Icons.Default.WifiOff else Icons.Default.WifiTethering,
                        contentDescription = null,
                        tint = if (isOff) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(36.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = if (isOff) "Ağ Taraması Duraklatıldı" else "Yakında Cihaz Aranıyor...",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = if (isOff) {
                    "Cihazları görmek için görünürlüğü 'Herkes' veya 'Bilinenler' olarak açın."
                } else {
                    "Masaüstünde OmaSend'in açık olduğundan emin olun. Cihazlar farklı ağdaysa Bluetooth eşleştirmesini kontrol edin."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 12.dp)
            )

            Spacer(modifier = Modifier.height(18.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                if (isOff) {
                    Button(
                        onClick = onEnableScan,
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Taramayı Başlat")
                    }
                } else {
                    OutlinedButton(
                        onClick = onAddDirectIp,
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Default.AddLink, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Doğrudan IP Ekle")
                    }
                }
            }
        }
    }
}

@Composable
fun RecentReceivedFilesCard(
    files: List<File>,
    onOpenFile: (File) -> Unit,
    onShareFile: (File) -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "SON ALINAN DOSYALAR",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary,
            letterSpacing = 0.8.sp,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
        )
        Spacer(modifier = Modifier.height(8.dp))

        ElevatedCard(
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.elevatedCardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp)
            ) {
                files.forEachIndexed { index, file ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpenFile(file) }
                            .padding(vertical = 8.dp, horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        val icon = getFileIcon(file.name)
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = MaterialTheme.colorScheme.surfaceContainerHigh,
                            modifier = Modifier.size(38.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    icon,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.width(12.dp))

                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = file.name,
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = NetworkUtils.formatBytes(file.length()),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        IconButton(
                            onClick = { onShareFile(file) },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                Icons.Default.Share,
                                contentDescription = "Paylaş",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(16.dp)
                            )
                        }

                        FilledTonalButton(
                            onClick = { onOpenFile(file) },
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            Text("Aç", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                    if (index < files.size - 1) {
                        HorizontalDivider(
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.3f),
                            modifier = Modifier.padding(vertical = 2.dp)
                        )
                    }
                }
            }
        }
    }
}

private fun getFileIcon(filename: String): ImageVector {
    val ext = filename.substringAfterLast('.', "").lowercase()
    return when (ext) {
        "jpg", "jpeg", "png", "webp", "gif", "svg" -> Icons.Default.Image
        "mp4", "mkv", "mov", "avi" -> Icons.Default.PlayCircle
        "mp3", "flac", "wav", "m4a" -> Icons.Default.MusicNote
        "pdf", "doc", "docx", "txt", "md" -> Icons.Default.Description
        "zip", "tar", "gz", "7z", "apk" -> Icons.Default.FolderZip
        else -> Icons.Default.InsertDriveFile
    }
}

// ------------------- DİALOGLAR -------------------

@Composable
fun TargetDeviceSelectionDialog(
    peers: List<DiscoveredPeer>,
    onDismiss: () -> Unit,
    onSelect: (DiscoveredPeer) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Gönderilecek Cihazı Seçin",
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.titleMedium
            )
        },
        text = {
            if (peers.isEmpty()) {
                Text(
                    text = "Şu anda yakında cihaz bulunamadı. Lütfen karşı cihazın OmaSend'i açık tuttuğundan emin olun.",
                    style = MaterialTheme.typography.bodyMedium
                )
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(peers) { peer ->
                        Surface(
                            onClick = { onSelect(peer) },
                            shape = RoundedCornerShape(12.dp),
                            color = MaterialTheme.colorScheme.surfaceContainerHigh,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    if (peer.transport == "BT") Icons.Default.Bluetooth else Icons.Default.Computer,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(24.dp)
                                )
                                Spacer(modifier = Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = peer.name,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        text = "${peer.ip} • ${peer.transport}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Icon(
                                    Icons.Default.ArrowForward,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("İptal")
            }
        }
    )
}

@Composable
fun RenameDeviceDialog(
    currentName: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit
) {
    var name by remember { mutableStateOf(currentName) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Cihaz Adını Değiştir",
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column {
                Text(
                    text = "Bu ad yakındaki cihazların ekranında görüntülenecektir:",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(10.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    label = { Text("Cihaz Adı") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val trimmed = name.trim()
                    if (trimmed.isNotEmpty()) onConfirm(trimmed)
                },
                enabled = name.trim().isNotEmpty()
            ) {
                Text("Kaydet")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("İptal")
            }
        }
    )
}

@Composable
fun IncomingTransferDialog(
    prompt: IncomingTransferPrompt,
    onAccept: () -> Unit,
    onDecline: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDecline,
        icon = {
            Icon(
                Icons.Default.Share,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(32.dp)
            )
        },
        title = {
            Text(
                text = "Dosya Aktarım İsteği",
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "'${prompt.senderName}' cihazından dosya gönderilmek isteniyor:",
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(12.dp))
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        prompt.files.forEach { file ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = file.name,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    modifier = Modifier.weight(1f),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = NetworkUtils.formatBytes(file.size_bytes),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onAccept) {
                Text("Kabul Et")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDecline) {
                Text("Reddet")
            }
        }
    )
}

@Composable
fun TransferStatusCard(
    state: TransferProgressState,
    onDismiss: () -> Unit
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            when (state) {
                is TransferProgressState.Requesting -> {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.5.dp)
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "'${state.peerName}' cihazına istek gönderiliyor...",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
                is TransferProgressState.WaitingConsent -> {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.5.dp)
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "'${state.peerName}' onayı bekleniyor...",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
                is TransferProgressState.Transferring -> {
                    Column {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = state.fileName,
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f)
                            )
                            Text(
                                text = "%${state.percent}",
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        LinearProgressIndicator(
                            progress = { state.percent / 100f },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "${NetworkUtils.formatBytes(state.bytesTransferred)} / ${NetworkUtils.formatBytes(state.totalBytes)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                is TransferProgressState.Success -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = Color(0xFF10B981))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = state.message,
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                        IconButton(onClick = onDismiss, modifier = Modifier.size(28.dp)) {
                            Icon(Icons.Default.Close, contentDescription = "Kapat", modifier = Modifier.size(16.dp))
                        }
                    }
                }
                is TransferProgressState.Error -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = state.message,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.error,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        IconButton(onClick = onDismiss, modifier = Modifier.size(28.dp)) {
                            Icon(Icons.Default.Close, contentDescription = "Kapat", modifier = Modifier.size(16.dp))
                        }
                    }
                }
                else -> {}
            }
        }
    }
}

@Composable
fun QrCodeDialog(
    context: Context,
    onDismiss: () -> Unit
) {
    val endpointUrl = "http://${NetworkUtils.getLocalIpAddress()}:53317"
    var qrBitmap by remember { mutableStateOf<Bitmap?>(null) }

    LaunchedEffect(endpointUrl) {
        withContext(Dispatchers.Default) {
            try {
                val writer = QRCodeWriter()
                val bitMatrix = writer.encode(endpointUrl, BarcodeFormat.QR_CODE, 512, 512)
                val width = bitMatrix.width
                val height = bitMatrix.height
                val bmp = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
                for (x in 0 until width) {
                    for (y in 0 until height) {
                        bmp.setPixel(x, y, if (bitMatrix.get(x, y)) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
                    }
                }
                qrBitmap = bmp
            } catch (_: Exception) {
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(text = "Web İndirme Portalı (QR)", fontWeight = FontWeight.Bold)
        },
        text = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Aynı ağdaki herhangi bir cihaz (iPhone, Mac, Windows veya PC) tarayıcıyla bu kodu okutarak bağlanabilir:",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(14.dp))

                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = Color.White,
                    modifier = Modifier.size(200.dp)
                ) {
                    Box(contentAlignment = Alignment.Center, modifier = Modifier.padding(12.dp)) {
                        if (qrBitmap != null) {
                            Image(
                                bitmap = qrBitmap!!.asImageBitmap(),
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
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
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
                                Toast.makeText(context, "URL kopyalandı", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = "Kopyala", modifier = Modifier.size(16.dp))
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) {
                Text("Tamam")
            }
        }
    )
}

@Composable
fun DirectIpDialog(
    onDismiss: () -> Unit,
    onConnect: (ip: String, port: Int) -> Unit
) {
    var ipText by remember { mutableStateOf("") }
    var portText by remember { mutableStateOf("53317") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(text = "Doğrudan IP ile Bağlan", fontWeight = FontWeight.Bold)
        },
        text = {
            Column {
                Text(
                    text = "Hedef cihazın IP adresini girin:",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = ipText,
                    onValueChange = { ipText = it },
                    label = { Text("IP Adresi (örn. 192.168.1.50)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = portText,
                    onValueChange = { portText = it },
                    label = { Text("Port") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val port = portText.toIntOrNull() ?: NetworkUtils.PORT
                    if (ipText.trim().isNotEmpty()) {
                        onConnect(ipText.trim(), port)
                    }
                },
                enabled = ipText.trim().isNotEmpty()
            ) {
                Text("Bağlan")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("İptal")
            }
        }
    )
}

@Composable
fun InfoDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(text = "OmaSend Hakkında", fontWeight = FontWeight.Bold)
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "OmaSend v1.0.3",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = "Omarchy Linux & Android Hibrit Paylaşım Ekosistemi",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(12.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(12.dp))
                InfoDialogRow("Ağ Protokolü", "P2P AirBridge + UDP Beacon (53317)")
                InfoDialogRow("Çevrimdışı Taşıma", "Bluetooth OBEX Push (OPP)")
                InfoDialogRow("Şifreleme & Bütünlük", "SHA-256 Checksum + Token Auth")
                InfoDialogRow("Geliştirici", "Ozan Özdil (Omarchy Linux)")
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) {
                Text("Kapat")
            }
        }
    )
}

@Composable
fun InfoDialogRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(text = value, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
    }
}

// ------------------- AKTARIM FONKSİYONLARI -------------------

suspend fun sendMultipleUrisToPeer(
    context: Context,
    app: OmaSendApp,
    peer: DiscoveredPeer,
    uris: List<Uri>,
    onState: (TransferProgressState) -> Unit
) {
    if (uris.isEmpty()) return
    for (uri in uris) {
        sendFileUriToPeer(context, app, peer, uri, onState)
    }
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

            // Bluetooth direct transfer
            if (peer.transport == "BT" || peer.ip.startsWith("bt:")) {
                withContext(Dispatchers.Main) {
                    onState(TransferProgressState.Idle)
                    TransferBridge.sendViaBluetooth(context, listOf(uri), targetMac = peer.fingerprint.ifEmpty { peer.ip })
                }
                return@withContext
            }

            withContext(Dispatchers.Main) {
                onState(TransferProgressState.Requesting(peer.name, fileName))
            }

            val fileInfo = TransferFileInfo(fileName, fileSize)
            val requestResult = app.client.sendTransferRequest(peer.ip, peer.port, listOf(fileInfo))

            val token = requestResult.getOrElse {
                if (peer.transport == "HYBRID" || peer.ip.startsWith("bt:")) {
                    withContext(Dispatchers.Main) {
                        onState(TransferProgressState.Idle)
                        Toast.makeText(context, "Wi-Fi bağlantısı kurulamadı. Bluetooth ile aktarılıyor...", Toast.LENGTH_LONG).show()
                        TransferBridge.sendViaBluetooth(context, listOf(uri), targetMac = peer.fingerprint.ifEmpty { peer.ip })
                    }
                    return@withContext
                }
                withContext(Dispatchers.Main) {
                    onState(TransferProgressState.Error(it.message ?: "Transfer isteği başarısız oldu"))
                }
                return@withContext
            }

            withContext(Dispatchers.Main) {
                onState(TransferProgressState.WaitingConsent(peer.name))
            }

            val decisionResult = app.client.pollDecision(peer.ip, peer.port, token)
            if (decisionResult.isFailure) {
                withContext(Dispatchers.Main) {
                    onState(TransferProgressState.Error(decisionResult.exceptionOrNull()?.message ?: "Transfer reddedildi"))
                }
                return@withContext
            }

            val inputStream = context.contentResolver.openInputStream(uri)
            if (inputStream == null) {
                withContext(Dispatchers.Main) {
                    onState(TransferProgressState.Error("Dosya akışı açılamadı"))
                }
                return@withContext
            }

            val uploadResult = app.client.uploadFileStream(
                targetIp = peer.ip,
                targetPort = peer.port,
                token = token,
                filename = fileName,
                totalBytes = fileSize,
                inputStream = inputStream
            ) { bytes: Long, total: Long, pct: Int ->
                scopeLaunchMain {
                    onState(TransferProgressState.Transferring(true, peer.name, fileName, bytes, total, pct))
                }
            }

            withContext(Dispatchers.Main) {
                if (uploadResult.isSuccess) {
                    onState(TransferProgressState.Success("'$fileName' başarıyla gönderildi!"))
                } else {
                    onState(TransferProgressState.Error(uploadResult.exceptionOrNull()?.message ?: "Yükleme başarısız"))
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                onState(TransferProgressState.Error(e.message ?: "Transfer hatası"))
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
    if (peer.transport == "BT" || peer.ip.startsWith("bt:")) {
        withContext(Dispatchers.Main) {
            Toast.makeText(context, "Pano senkronizasyonu yalnızca Wi-Fi (LAN) bağlantısıyla desteklenir.", Toast.LENGTH_SHORT).show()
        }
        return
    }

    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    val clip = clipboard?.primaryClip
    val text = if (clip != null && clip.itemCount > 0) clip.getItemAt(0).text?.toString() else null

    if (text.isNullOrEmpty()) {
        withContext(Dispatchers.Main) {
            Toast.makeText(context, "Telefon panosu boş! Önce bir metin kopyalayın.", Toast.LENGTH_SHORT).show()
        }
        return
    }

    withContext(Dispatchers.IO) {
        val result = app.client.sendClipboard(peer.ip, peer.port, text)
        withContext(Dispatchers.Main) {
            if (result.isSuccess) {
                Toast.makeText(context, "Pano metni '${peer.name}' cihazına aktarıldı!", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(context, "Pano aktarılamadı: ${result.exceptionOrNull()?.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
}

private fun scopeLaunchMain(block: () -> Unit) {
    android.os.Handler(android.os.Looper.getMainLooper()).post(block)
}

// ------------------- DOSYA YARDIMCILARI -------------------

fun getRecentReceivedFiles(): List<File> {
    return try {
        val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "OmaSend")
        if (dir.exists() && dir.isDirectory) {
            dir.listFiles()
                ?.filter { it.isFile && !it.name.startsWith(".") && !it.name.endsWith(".part") }
                ?.sortedByDescending { it.lastModified() }
                ?.take(5) ?: emptyList()
        } else {
            emptyList()
        }
    } catch (_: Exception) {
        emptyList()
    }
}

fun openFileWithSystem(context: Context, file: File) {
    try {
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.provider",
            file
        )
        val ext = file.extension.lowercase()
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "*/*"
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mime)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    } catch (e: Exception) {
        Toast.makeText(context, "Dosya açılamadı: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
    }
}

fun shareFileWithSystem(context: Context, file: File) {
    try {
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.provider",
            file
        )
        val ext = file.extension.lowercase()
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "*/*"
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = mime
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Dosyayı Paylaş"))
    } catch (e: Exception) {
        Toast.makeText(context, "Paylaşılamadı: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
    }
}

@Composable
fun PeerCard(
    peer: DiscoveredPeer,
    isSelected: Boolean = false,
    onClick: () -> Unit,
    onSendFile: () -> Unit = {},
    onSendClipboard: () -> Unit = {}
) {
    ModernPeerCard(
        peer = peer,
        isSelected = isSelected,
        onCardClick = onClick,
        onSendClick = onSendFile,
        onClipboardClick = onSendClipboard
    )
}

