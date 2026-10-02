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
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.layout.ContentScale
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
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
import io.omarchy.omasend.crypto.OmaIdentity
import io.omarchy.omasend.model.*
import io.omarchy.omasend.ui.scanner.OmaQrScannerDialog
import io.omarchy.omasend.network.NetworkTransportMode
import io.omarchy.omasend.network.NetworkUtils
import io.omarchy.omasend.network.TransferBridge
import io.omarchy.omasend.network.WanStatus
import io.omarchy.omasend.service.OmaSendForegroundService
import io.omarchy.omasend.ui.theme.JetBrainsMonoFontFamily
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
    val clipboardEntries by app.clipboardVault.entries.collectAsState()
    var omaIdentity by remember { mutableStateOf(app.omaIdentity) }
    val wanStatus by app.wanDiscoveryEngine.status.collectAsState()

    var selectedPeer by remember { mutableStateOf<DiscoveredPeer?>(null) }
    var transferState by remember { mutableStateOf<TransferProgressState>(TransferProgressState.Idle) }

    var showInfoDialog by remember { mutableStateOf(false) }
    var showQrDialog by remember { mutableStateOf(false) }
    var showDirectIpDialog by remember { mutableStateOf(false) }
    var showRenameDialog by remember { mutableStateOf(false) }
    var showTargetSelectorDialog by remember { mutableStateOf(false) }
    var showClipboardVaultDialog by remember { mutableStateOf(false) }
    var previewImageEntry by remember { mutableStateOf<ClipboardEntry?>(null) }
    var showOmaIdQrDialog by remember { mutableStateOf(false) }
    var showQrScannerDialog by remember { mutableStateOf(false) }
    var showEditOmaIdDialog by remember { mutableStateOf(false) }
    var showResetOmaIdConfirmDialog by remember { mutableStateOf(false) }
    var showNetworkStatusDialog by remember { mutableStateOf(false) }
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
                                app.discoveryManager.forceRefresh()
                                refreshRecentFiles()
                                isRefreshing = false
                                Toast.makeText(context, "Ağ eşleri ve OmaID bağlantıları güncellendi", Toast.LENGTH_SHORT).show()
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
                        onClick = { showQrScannerDialog = true },
                        modifier = Modifier.size(38.dp)
                    ) {
                        Icon(
                            Icons.Default.QrCodeScanner,
                            contentDescription = "OmaID QR / Barkod Tara",
                            modifier = Modifier.size(20.dp),
                            tint = Color(0xFF38BDF8)
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
                        onClick = { showClipboardVaultDialog = true },
                        modifier = Modifier.size(38.dp)
                    ) {
                        Icon(
                            Icons.Default.ContentPaste,
                            contentDescription = "Pano Hafızası",
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
            // 1. OmaID Kimlik Kapsülü ve Ağ Durumu
            item {
                OmaIdCapsuleCard(
                    identity = omaIdentity,
                    wanStatus = wanStatus,
                    onCopyId = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        val clip = ClipData.newPlainText("OmaID", omaIdentity.formattedId)
                        clipboard?.setPrimaryClip(clip)
                        Toast.makeText(context, "OmaID panoya kopyalandı", Toast.LENGTH_SHORT).show()
                    },
                    onShowQr = { showOmaIdQrDialog = true },
                    onScanQr = { showQrScannerDialog = true },
                    onEditId = { showEditOmaIdDialog = true },
                    onResetId = { showResetOmaIdConfirmDialog = true },
                    onNetworkStatusClick = { showNetworkStatusDialog = true }
                )
            }

            // 2. Cihazım ve Görünürlük Kartı
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
                    onOpenClipboardVault = {
                        showClipboardVaultDialog = true
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
                        discoveryMode = discoveryMode,
                        onEnableScan = {
                            app.discoveryManager.setMode(DiscoveryMode.EVERYONE)
                            OmaSendForegroundService.startService(context)
                        },
                        onSwitchToEveryone = {
                            app.discoveryManager.setMode(DiscoveryMode.EVERYONE)
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
                        onToggleTrust = {
                            app.discoveryManager.toggleTrust(peer.id)
                        },
                        onSendClick = {
                            selectedPeer = peer
                            singlePeerFilePicker.launch("*/*")
                        }
                    )
                }
            }

            // 5. Canli Pano Hafizasi (Clipboard Vault - Son Kopyalananlar)
            if (clipboardEntries.isNotEmpty()) {
                item {
                    ClipboardVaultHeroCard(
                        app = app,
                        entries = clipboardEntries.take(6),
                        totalCount = clipboardEntries.size,
                        onOpenVault = { showClipboardVaultDialog = true },
                        onPreviewImage = { entry -> previewImageEntry = entry }
                    )
                }
            }

            // 6. Son Alınan Dosyalar (Ekstra Kolaylık Özelliği)
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

    if (showClipboardVaultDialog) {
        ClipboardVaultDialog(
            app = app,
            onDismiss = { showClipboardVaultDialog = false },
            onPreviewImage = { entry -> previewImageEntry = entry }
        )
    }

    if (previewImageEntry != null) {
        ClipboardImagePreviewDialog(
            app = app,
            entry = previewImageEntry!!,
            onDismiss = { previewImageEntry = null }
        )
    }

    if (showOmaIdQrDialog) {
        OmaIdQrDialog(
            identity = omaIdentity,
            onDismiss = { showOmaIdQrDialog = false }
        )
    }

    if (showQrScannerDialog) {
        OmaQrScannerDialog(
            onDismissRequest = { showQrScannerDialog = false },
            onOmaIdConnected = { scannedId ->
                showQrScannerDialog = false
                scope.launch {
                    val formatted = OmaIdentity.format(scannedId)
                    app.discoveryManager.addPairedOmaId(formatted)
                    app.discoveryManager.forceRefresh()
                    Toast.makeText(context, "OmaID eşleşti: $formatted", Toast.LENGTH_LONG).show()
                }
            }
        )
    }

    if (showEditOmaIdDialog) {
        EditOmaIdDialog(
            currentId = omaIdentity.formattedId,
            onDismiss = { showEditOmaIdDialog = false },
            onSave = { newId ->
                try {
                    omaIdentity = app.setCustomOmaIdentity(newId)
                    showEditOmaIdDialog = false
                    Toast.makeText(context, "OmaID başarıyla güncellendi", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    Toast.makeText(context, "Hata: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        )
    }

    if (showResetOmaIdConfirmDialog) {
        ResetOmaIdConfirmDialog(
            onDismiss = { showResetOmaIdConfirmDialog = false },
            onConfirm = {
                omaIdentity = app.resetOmaIdentity()
                showResetOmaIdConfirmDialog = false
                Toast.makeText(context, "Yeni OmaID üretildi", Toast.LENGTH_SHORT).show()
            }
        )
    }

    if (showNetworkStatusDialog) {
        NetworkStatusDialog(
            wanStatus = wanStatus,
            identity = omaIdentity,
            onDismiss = { showNetworkStatusDialog = false },
            onSwitchMode = { newMode ->
                app.wanDiscoveryEngine.setNetworkMode(newMode)
                Toast.makeText(context, "Ağ Modu: ${newMode.name}", Toast.LENGTH_SHORT).show()
            }
        )
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
fun OptimizedRadarPulseAvatar(
    isScanning: Boolean,
    modifier: Modifier = Modifier
) {
    if (isScanning) {
        val infiniteTransition = rememberInfiniteTransition(label = "SingleNodeWaterRippleRadar")
        val waveProgress by infiniteTransition.animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = tween(2200, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "WaterWaveProgress"
        )
        val primaryColor = MaterialTheme.colorScheme.primary

        Box(
            modifier = modifier
                .size(56.dp)
                .drawWithCache {
                    onDrawBehind {
                        val center = Offset(size.width / 2f, size.height / 2f)
                        val maxRadius = size.minDimension * 0.96f
                        val baseRadius = size.minDimension * 0.38f

                        // 4 Staggered concentric ripple phases with quadratic decay
                        val numWaves = 4
                        for (i in 0 until numWaves) {
                            val phase = (waveProgress + i.toFloat() / numWaves) % 1.0f
                            // Smooth outward deceleration curve
                            val easedPhase = 1f - (1f - phase) * (1f - phase)
                            val currentRadius = baseRadius + (maxRadius - baseRadius) * easedPhase
                            
                            // Quadratic alpha decay for smooth edge dissipation
                            val alpha = ((1f - phase) * (1f - phase) * 0.85f).coerceIn(0f, 1f)
                            val strokeWidth = (2.2f * (1f - phase * 0.6f)).dp.toPx()

                            // Translucent water body fill
                            drawCircle(
                                color = primaryColor.copy(alpha = alpha * 0.12f),
                                radius = currentRadius,
                                center = center
                            )
                            // Sharp water ripple wavefront border
                            drawCircle(
                                color = primaryColor.copy(alpha = alpha * 0.85f),
                                radius = currentRadius,
                                center = center,
                                style = Stroke(width = strokeWidth)
                            )
                        }
                    }
                },
            contentAlignment = Alignment.Center
        ) {
            // Center Droplet Core
            Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.primaryContainer,
                border = BorderStroke(1.5.dp, MaterialTheme.colorScheme.primary),
                modifier = Modifier.size(46.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        Icons.Default.PhoneAndroid,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(24.dp)
                    )
                }
            }
        }
    } else {
        Surface(
            shape = CircleShape,
            color = MaterialTheme.colorScheme.surfaceVariant,
            modifier = modifier.size(46.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    Icons.Default.PhoneAndroid,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(24.dp)
                )
            }
        }
    }
}

@Composable
fun RadarPulseAvatar(
    isScanning: Boolean,
    modifier: Modifier = Modifier
) {
    OptimizedRadarPulseAvatar(isScanning = isScanning, modifier = modifier)
}

@Composable
fun LocalDeviceHeroCard(
    context: Context,
    currentMode: DiscoveryMode,
    onModeSelected: (DiscoveryMode) -> Unit,
    onRename: () -> Unit
) {
    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.40f), RoundedCornerShape(20.dp)),
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
                RadarPulseAvatar(isScanning = currentMode != DiscoveryMode.OFF)

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
    onOpenClipboardVault: () -> Unit,
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
                title = "Pano Hafızası",
                icon = Icons.Default.ContentPaste,
                modifier = Modifier.weight(1f),
                onClick = onOpenClipboardVault
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
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.35f)),
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
    onToggleTrust: () -> Unit = {},
    onSendClick: () -> Unit
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
                else Modifier.border(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.40f), RoundedCornerShape(18.dp))
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
                    "WAN" -> MaterialTheme.colorScheme.secondaryContainer
                    "DIRECT" -> MaterialTheme.colorScheme.tertiaryContainer
                    else -> MaterialTheme.colorScheme.primaryContainer
                },
                modifier = Modifier.size(46.dp)
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
                        tint = when (peer.transport) {
                            "WAN" -> MaterialTheme.colorScheme.onSecondaryContainer
                            "DIRECT" -> MaterialTheme.colorScheme.onTertiaryContainer
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
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    IconButton(
                        onClick = onToggleTrust,
                        modifier = Modifier.size(24.dp)
                    ) {
                        Icon(
                            if (peer.isTrusted) Icons.Default.Star else Icons.Default.StarBorder,
                            contentDescription = if (peer.isTrusted) "Güvenilen Cihaz" else "Güvenilir Olarak İşaretle",
                            tint = if (peer.isTrusted) Color(0xFFF59E0B) else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(2.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val isPaired = peer.isTrusted || peer.omaId.isNotEmpty()
                    val transportLabel = when {
                        peer.transport == "WAN" -> "WAN"
                        peer.transport == "DIRECT" -> "DIRECT"
                        isPaired -> "OMAID"
                        else -> "LAN"
                    }
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = when (transportLabel) {
                            "WAN" -> MaterialTheme.colorScheme.secondary.copy(alpha = 0.15f)
                            "DIRECT" -> MaterialTheme.colorScheme.tertiary.copy(alpha = 0.15f)
                            "OMAID" -> Color(0xFF10B981).copy(alpha = 0.15f)
                            else -> MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)
                        }
                    ) {
                        Text(
                            text = transportLabel,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = when (transportLabel) {
                                "WAN" -> MaterialTheme.colorScheme.secondary
                                "DIRECT" -> MaterialTheme.colorScheme.tertiary
                                "OMAID" -> Color(0xFF059669)
                                else -> MaterialTheme.colorScheme.primary
                            }
                        )
                    }
                    if (peer.isTrusted) {
                        Spacer(modifier = Modifier.width(4.dp))
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = Color(0xFFF59E0B).copy(alpha = 0.15f)
                        ) {
                            Text(
                                text = "EŞLEŞMİŞ",
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFFD97706)
                            )
                        }
                    }
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (peer.omaId.isNotEmpty()) OmaIdentity.format(peer.omaId) else "${peer.ip}:${peer.port}",
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
    discoveryMode: DiscoveryMode,
    onEnableScan: () -> Unit,
    onSwitchToEveryone: () -> Unit,
    onAddDirectIp: () -> Unit
) {
    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.40f), RoundedCornerShape(20.dp)),
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
                        when (discoveryMode) {
                            DiscoveryMode.OFF -> Icons.Default.WifiOff
                            DiscoveryMode.KNOWN_PEERS -> Icons.Default.Security
                            DiscoveryMode.EVERYONE -> Icons.Default.WifiTethering
                        },
                        contentDescription = null,
                        tint = if (discoveryMode == DiscoveryMode.OFF) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(36.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = when (discoveryMode) {
                    DiscoveryMode.OFF -> "Ağ Taraması Duraklatıldı"
                    DiscoveryMode.KNOWN_PEERS -> "Kayıtlı Güvenilir Cihaz Yok"
                    DiscoveryMode.EVERYONE -> "Yakında Cihaz Aranıyor..."
                },
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = when (discoveryMode) {
                    DiscoveryMode.OFF -> "Cihazları görmek için görünürlüğü 'Herkes' veya 'Bilinenler' olarak açın."
                    DiscoveryMode.KNOWN_PEERS -> "Yalnızca güvenilir olarak işaretlenen veya eşleşen cihazlar listelenir. Yakındaki tüm cihazları görmek için 'Herkes' moduna geçebilirsiniz."
                    DiscoveryMode.EVERYONE -> "Masaüstünde OmaSend'in açık olduğundan emin olun. Cihazlar farklı ağdaysa OmaID QR kodu ile eşleştirmeyi kontrol edin."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 12.dp)
            )

            Spacer(modifier = Modifier.height(18.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                when (discoveryMode) {
                    DiscoveryMode.OFF -> {
                        Button(
                            onClick = onEnableScan,
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text("Taramayı Başlat")
                        }
                    }
                    DiscoveryMode.KNOWN_PEERS -> {
                        Button(
                            onClick = onSwitchToEveryone,
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Icon(Icons.Default.Public, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Herkes Moduna Geç")
                        }
                        OutlinedButton(
                            onClick = onAddDirectIp,
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Icon(Icons.Default.AddLink, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Doğrudan IP Ekle")
                        }
                    }
                    DiscoveryMode.EVERYONE -> {
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
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.40f), RoundedCornerShape(18.dp))
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
                                    if (peer.name.lowercase().contains("phone") || peer.name.lowercase().contains("android")) Icons.Default.PhoneAndroid else Icons.Default.Computer,
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
                                        text = if (peer.omaId.isNotEmpty()) "${peer.ip} • OmaID: ${OmaIdentity.format(peer.omaId)}" else "${peer.ip} • ${peer.transport}",
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
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "${NetworkUtils.formatBytes(state.bytesTransferred)} / ${NetworkUtils.formatBytes(state.totalBytes)}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            val speedText = if (state.speedMBps > 0.0) {
                                String.format(java.util.Locale.US, "%.1f MB/s", state.speedMBps)
                            } else ""
                            val etaText = if (state.etaSeconds > 0L) {
                                " • ETA: ${state.etaSeconds}s"
                            } else ""
                            if (speedText.isNotEmpty() || etaText.isNotEmpty()) {
                                Text(
                                    text = "$speedText$etaText",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
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
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(text = "OmaSend Hakkında", fontWeight = FontWeight.Bold)
            }
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            text = "OmaSend v1.3.3 (27)",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "Omarchy Linux & Android Hibrit Paylaşım Ekosistemi",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        InfoDialogRow("Ağ Protokolü", "P2P AirBridge + UDP Beacon (53317)")
                        InfoDialogRow("Uçtan Uca Kimlik", "16 Haneli Luhn OmaID + Rendezvous")
                        InfoDialogRow("Şifreleme & Bütünlük", "AES-256-GCM + SHA-256 Checksum")
                        InfoDialogRow("Geliştirici", "Ozan Özdil (Omarchy Linux)")
                    }
                }

                // Buy Me a Coffee & GitHub Action Buttons
                Button(
                    onClick = {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://buymeacoffee.com/ozdil"))
                        context.startActivity(intent)
                    },
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFFFFDD00),
                        contentColor = Color(0xFF000000)
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(
                        Icons.Default.Favorite,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = Color(0xFF000000)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Buy Me a Coffee",
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.labelLarge
                    )
                }

                OutlinedButton(
                    onClick = {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/ozdil"))
                        context.startActivity(intent)
                    },
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(
                        Icons.Default.Code,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "GitHub / Kaynak Kod",
                        fontWeight = FontWeight.SemiBold,
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onDismiss,
                shape = RoundedCornerShape(10.dp)
            ) {
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

            withContext(Dispatchers.Main) {
                onState(TransferProgressState.Requesting(peer.name, fileName))
            }

            val fileInfo = TransferFileInfo(fileName, fileSize)
            val requestResult = app.client.sendTransferRequest(peer.ip, peer.port, listOf(fileInfo))

            val token = requestResult.getOrElse {
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

            val uploadResult = app.client.uploadFileStreamWithMetrics(
                targetIp = peer.ip,
                targetPort = peer.port,
                token = token,
                filename = fileName,
                totalBytes = fileSize,
                inputStream = inputStream
            ) { bytes: Long, total: Long, pct: Int, speedMBps: Double, etaSeconds: Long ->
                scopeLaunchMain {
                    onState(TransferProgressState.Transferring(true, peer.name, fileName, bytes, total, pct, speedMBps, etaSeconds))
                }
            }

            withContext(Dispatchers.Main) {
                if (uploadResult.isSuccess) {
                    app.soundEngine.playSendSound()
                    app.hapticController.onDropBounce()
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
    if (peer.port <= 0) return

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
            "${context.packageName}.fileprovider",
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
            "${context.packageName}.fileprovider",
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
    onSendFile: () -> Unit = {}
) {
    ModernPeerCard(
        peer = peer,
        isSelected = isSelected,
        onCardClick = onClick,
        onSendClick = onSendFile
    )
}

fun getDeviceTypeBadge(senderName: String): String {
    val lower = senderName.lowercase()
    return when {
        lower.contains("pc") || lower.contains("desktop") || lower.contains("laptop") || lower.contains("arch") || lower.contains("linux") || lower.contains("omarchy") -> "Masaüstü"
        lower.contains("phone") || lower.contains("android") || lower.contains("mobile") || lower.contains("pixel") || lower.contains("samsung") || lower.contains("xiaomi") -> "Telefon"
        else -> senderName
    }
}

fun copyImageToClipboard(context: Context, app: OmaSendApp, file: File) {
    try {
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val clip = ClipData.newUri(context.contentResolver, "OmaSend Image", uri)
        clipboard?.setPrimaryClip(clip)
        app.hapticController.onClipTick()
        Toast.makeText(context, "Görsel panoya kopyalandı", Toast.LENGTH_SHORT).show()
    } catch (e: Exception) {
        Toast.makeText(context, "Panoya kopyalanamadı: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
    }
}

fun saveImageToGallery(context: Context, imageFile: File): Boolean {
    return try {
        val filename = "OmaSend_${System.currentTimeMillis()}.png"
        val values = android.content.ContentValues().apply {
            put(android.provider.MediaStore.Images.Media.DISPLAY_NAME, filename)
            put(android.provider.MediaStore.Images.Media.MIME_TYPE, "image/png")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                put(android.provider.MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/OmaSend")
                put(android.provider.MediaStore.Images.Media.IS_PENDING, 1)
            }
        }
        val uri = context.contentResolver.insert(android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)
            ?: return false
        context.contentResolver.openOutputStream(uri)?.use { out ->
            imageFile.inputStream().use { input ->
                input.copyTo(out)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            values.clear()
            values.put(android.provider.MediaStore.Images.Media.IS_PENDING, 0)
            context.contentResolver.update(uri, values, null, null)
        }
        true
    } catch (_: Exception) {
        false
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ClipboardImageVaultItem(
    app: OmaSendApp,
    item: ClipboardEntry,
    onPreview: () -> Unit
) {
    val context = LocalContext.current
    val hash = item.imageHash ?: ""
    val file = remember(hash) { app.clipboardVault.getImageFile(hash) }
    val thumbFile = remember(hash) { app.clipboardVault.getThumbnailFile(hash) }
    var bitmap by remember(hash) { mutableStateOf<androidx.compose.ui.graphics.ImageBitmap?>(null) }
    val timeFormat = remember { java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()) }

    LaunchedEffect(hash, item.thumbnailBase64) {
        withContext(Dispatchers.IO) {
            // 1. Önce <hash>_thumb.webp dosyası
            if (thumbFile.exists() && thumbFile.length() > 0) {
                try {
                    val bmp = android.graphics.BitmapFactory.decodeFile(thumbFile.absolutePath)
                    if (bmp != null) {
                        bitmap = bmp.asImageBitmap()
                        return@withContext
                    }
                } catch (_: Exception) {}
            }

            // 2. Yoksa entry.thumbnailBase64 çözümlenir
            if (!item.thumbnailBase64.isNullOrBlank()) {
                try {
                    val bytes = io.omarchy.omasend.engine.ThumbnailEngine.decodeBase64(item.thumbnailBase64)
                    if (bytes != null && bytes.isNotEmpty()) {
                        val bmp = android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                        if (bmp != null) {
                            bitmap = bmp.asImageBitmap()
                            return@withContext
                        }
                    }
                } catch (_: Exception) {}
            }

            // 3. Dosya sistemindeki ana görselden thumbnail türetme veya yükleme
            if (file.exists() && file.length() > 0) {
                try {
                    val res = io.omarchy.omasend.engine.ThumbnailEngine.generateAndCacheThumbnail(
                        context,
                        file.readBytes(),
                        hash
                    )
                    if (res.file != null && res.file.exists() && res.file.length() > 0) {
                        val bmp = android.graphics.BitmapFactory.decodeFile(res.file.absolutePath)
                        if (bmp != null) {
                            bitmap = bmp.asImageBitmap()
                            return@withContext
                        }
                    }
                    val bmp = android.graphics.BitmapFactory.decodeFile(file.absolutePath)
                    if (bmp != null) {
                        bitmap = bmp.asImageBitmap()
                        return@withContext
                    }
                } catch (_: Exception) {}
            }
        }
    }

    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = {
                    if (file.exists() && file.length() > 0) {
                        copyImageToClipboard(context, app, file)
                    } else {
                        onPreview()
                    }
                },
                onLongClick = onPreview
            ),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.surfaceContainerHighest)
                    .clickable { onPreview() },
                contentAlignment = Alignment.Center
            ) {
                if (bitmap != null) {
                    Image(
                        bitmap = bitmap!!,
                        contentDescription = "Önizleme",
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Crop
                    )
                } else {
                    Icon(
                        Icons.Default.Image,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(22.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = if (item.isMine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.secondaryContainer
                        ) {
                            Text(
                                text = if (item.isMine) "Bu Cihaz" else getDeviceTypeBadge(item.senderName),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = if (item.isMine) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSecondaryContainer,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }

                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = MaterialTheme.colorScheme.tertiaryContainer
                        ) {
                            val sizeLabel = item.imageSize?.let { NetworkUtils.formatBytes(it) } ?: ""
                            Text(
                                text = if (sizeLabel.isNotBlank()) "$sizeLabel PNG" else "PNG",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onTertiaryContainer,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }

                    Text(
                        text = timeFormat.format(java.util.Date(item.timestamp)),
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Spacer(modifier = Modifier.height(4.dp))

                Text(
                    text = if (item.width != null && item.height != null) "${item.width} x ${item.height}" else "Görsel Pano Öğesi",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            IconButton(
                onClick = {
                    if (file.exists() && file.length() > 0) {
                        copyImageToClipboard(context, app, file)
                    } else {
                        onPreview()
                    }
                },
                modifier = Modifier.size(32.dp)
            ) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = "Panoya Kopyala",
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}

@Composable
fun ClipboardImagePreviewDialog(
    app: OmaSendApp,
    entry: ClipboardEntry,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val hash = entry.imageHash ?: ""
    val file = remember(hash) { app.clipboardVault.getImageFile(hash) }
    val thumbFile = remember(hash) { app.clipboardVault.getThumbnailFile(hash) }
    var bitmap by remember(hash) { mutableStateOf<androidx.compose.ui.graphics.ImageBitmap?>(null) }
    var isLoading by remember { mutableStateOf(false) }

    LaunchedEffect(hash) {
        withContext(Dispatchers.IO) {
            if (file.exists() && file.length() > 0) {
                try {
                    val bmp = android.graphics.BitmapFactory.decodeFile(file.absolutePath)
                    if (bmp != null) {
                        bitmap = bmp.asImageBitmap()
                        return@withContext
                    }
                } catch (_: Exception) {}
            }
            if (thumbFile.exists() && thumbFile.length() > 0) {
                try {
                    val bmp = android.graphics.BitmapFactory.decodeFile(thumbFile.absolutePath)
                    if (bmp != null) {
                        bitmap = bmp.asImageBitmap()
                    }
                } catch (_: Exception) {}
            } else if (!entry.thumbnailBase64.isNullOrBlank()) {
                try {
                    val bytes = io.omarchy.omasend.engine.ThumbnailEngine.decodeBase64(entry.thumbnailBase64)
                    if (bytes != null && bytes.isNotEmpty()) {
                        val bmp = android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                        if (bmp != null) {
                            bitmap = bmp.asImageBitmap()
                        }
                    }
                } catch (_: Exception) {}
            }
            if (!file.exists() || file.length() == 0L) {
                isLoading = true
                val peers = app.discoveryManager.peers.value
                val peer = peers.firstOrNull { it.name == entry.senderName }
                if (peer != null && peer.port > 0) {
                    val fetched = app.clipboardVault.fetchAndCacheImage(app.client, peer.ip, peer.port, hash)
                    if (fetched != null && fetched.exists()) {
                        try {
                            val bmp = android.graphics.BitmapFactory.decodeFile(fetched.absolutePath)
                            if (bmp != null) {
                                bitmap = bmp.asImageBitmap()
                            }
                        } catch (_: Exception) {}
                    }
                }
                isLoading = false
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Görsel Önizleme",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.titleMedium
                )
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = MaterialTheme.colorScheme.primaryContainer
                ) {
                    val sizeLabel = entry.imageSize?.let { NetworkUtils.formatBytes(it) } ?: ""
                    Text(
                        text = if (sizeLabel.isNotBlank()) "$sizeLabel PNG" else "PNG",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 160.dp, max = 320.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerHighest),
                    contentAlignment = Alignment.Center
                ) {
                    if (bitmap != null) {
                        Image(
                            bitmap = bitmap!!,
                            contentDescription = "Pano Görseli",
                            modifier = Modifier.fillMaxWidth(),
                            contentScale = ContentScale.Fit
                        )
                    } else if (isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(36.dp))
                    } else {
                        Icon(
                            Icons.Default.Image,
                            contentDescription = null,
                            modifier = Modifier.size(48.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val senderBadge = if (entry.isMine) "Bu Cihaz" else getDeviceTypeBadge(entry.senderName)
                    Text(
                        text = "Kaynak: $senderBadge",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (entry.width != null && entry.height != null) {
                        Text(
                            text = "${entry.width} x ${entry.height}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        },
        confirmButton = {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = {
                        val saved = saveImageToGallery(context, file)
                        if (saved) {
                            app.hapticController.onClipTick()
                            Toast.makeText(context, "Galeriye kaydedildi", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(context, "Galeriye kaydedilemedi", Toast.LENGTH_SHORT).show()
                        }
                    }
                ) {
                    Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Galeriye Kaydet")
                }
                Button(
                    onClick = {
                        if (file.exists() && file.length() > 0) {
                            copyImageToClipboard(context, app, file)
                        } else {
                            Toast.makeText(context, "Görsel henüz indirilmedi", Toast.LENGTH_SHORT).show()
                        }
                    }
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Kopyala")
                }
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
fun ClipboardVaultHeroCard(
    app: OmaSendApp,
    entries: List<ClipboardEntry>,
    totalCount: Int,
    onOpenVault: () -> Unit,
    onPreviewImage: (ClipboardEntry) -> Unit
) {
    val context = LocalContext.current
    val timeFormat = remember { java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()) }

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 2.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "PANO HAFIZASI",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary,
                    letterSpacing = 0.8.sp
                )
                Spacer(modifier = Modifier.width(8.dp))
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)
                ) {
                    Text(
                        text = "CANLI SENKRON",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }

            TextButton(
                onClick = onOpenVault,
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
            ) {
                Text(
                    text = "Tümü ($totalCount)",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            entries.forEach { item ->
                if (item.contentType == "image" || item.imageHash != null) {
                    ClipboardImageVaultItem(
                        app = app,
                        item = item,
                        onPreview = { onPreviewImage(item) }
                    )
                } else {
                    ElevatedCard(
                        onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                            val clip = ClipData.newPlainText("OmaSend", item.text)
                            app.clipboardVault.updateLastReceivedHash(item.text)
                            clipboard?.setPrimaryClip(clip)
                            app.hapticController.onClipTick()
                            Toast.makeText(context, "Panoya kopyalandı", Toast.LENGTH_SHORT).show()
                        },
                        shape = RoundedCornerShape(14.dp),
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
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Surface(
                                    shape = RoundedCornerShape(6.dp),
                                    color = if (item.isMine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.secondaryContainer
                                ) {
                                    Text(
                                        text = if (item.isMine) "Bu Cihaz" else getDeviceTypeBadge(item.senderName),
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = if (item.isMine) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSecondaryContainer,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }

                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = timeFormat.format(java.util.Date(item.timestamp)),
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Icon(
                                        Icons.Default.ContentCopy,
                                        contentDescription = "Panoya Kopyala",
                                        tint = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.size(14.dp)
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(6.dp))

                            Text(
                                text = item.text,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ClipboardVaultDialog(
    app: OmaSendApp,
    onDismiss: () -> Unit,
    onPreviewImage: (ClipboardEntry) -> Unit
) {
    val context = LocalContext.current
    val entries by app.clipboardVault.entries.collectAsState()
    val timeFormat = remember { java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Pano Hafızası",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.titleMedium
                )
                if (entries.isNotEmpty()) {
                    TextButton(
                        onClick = {
                            app.clipboardVault.clear()
                            Toast.makeText(context, "Pano geçmişi temizlendi", Toast.LENGTH_SHORT).show()
                        }
                    ) {
                        Text(
                            text = "Temizle",
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }
            }
        },
        text = {
            if (entries.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "Kayıtlı pano öğesi bulunmuyor",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 420.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(entries, key = { it.id }) { item ->
                        if (item.contentType == "image" || item.imageHash != null) {
                            ClipboardImageVaultItem(
                                app = app,
                                item = item,
                                onPreview = { onPreviewImage(item) }
                            )
                        } else {
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = MaterialTheme.colorScheme.surfaceContainerHigh,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(10.dp)
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Surface(
                                            shape = RoundedCornerShape(6.dp),
                                            color = if (item.isMine) {
                                                MaterialTheme.colorScheme.primaryContainer
                                            } else {
                                                MaterialTheme.colorScheme.secondaryContainer
                                            }
                                        ) {
                                            Text(
                                                text = if (item.isMine) "Yerel" else "Gelen: ${getDeviceTypeBadge(item.senderName)}",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.Bold,
                                                color = if (item.isMine) {
                                                    MaterialTheme.colorScheme.onPrimaryContainer
                                                } else {
                                                    MaterialTheme.colorScheme.onSecondaryContainer
                                                },
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                            )
                                        }
                                        Text(
                                            text = timeFormat.format(java.util.Date(item.timestamp)),
                                            style = MaterialTheme.typography.labelSmall,
                                            fontFamily = FontFamily.Monospace,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text(
                                        text = item.text,
                                        style = MaterialTheme.typography.bodySmall,
                                        fontFamily = FontFamily.Monospace,
                                        maxLines = 3,
                                        overflow = TextOverflow.Ellipsis,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.End
                                    ) {
                                        TextButton(
                                            onClick = {
                                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                                                val clip = ClipData.newPlainText("OmaSend", item.text)
                                                app.clipboardVault.updateLastReceivedHash(item.text)
                                                clipboard?.setPrimaryClip(clip)
                                                app.hapticController.onClipTick()
                                                Toast.makeText(context, "Panoya kopyalandı", Toast.LENGTH_SHORT).show()
                                            },
                                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                                        ) {
                                            Icon(
                                                Icons.Default.ContentCopy,
                                                contentDescription = null,
                                                modifier = Modifier.size(14.dp)
                                            )
                                            Spacer(modifier = Modifier.width(4.dp))
                                            Text(text = "Kopyala", style = MaterialTheme.typography.labelSmall)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) {
                Text("Kapat")
            }
        }
    )
}

// ------------------- OMAID VE AĞ DURUMU BİLEŞENLERİ -------------------

@Composable
fun OmaIdCapsuleCard(
    identity: OmaIdentity,
    wanStatus: WanStatus,
    onCopyId: () -> Unit,
    onShowQr: () -> Unit,
    onScanQr: () -> Unit,
    onEditId: () -> Unit,
    onResetId: () -> Unit,
    onNetworkStatusClick: () -> Unit
) {
    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.40f), RoundedCornerShape(20.dp)),
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
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        shape = CircleShape,
                        color = MaterialTheme.colorScheme.primaryContainer,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                Icons.Default.Shield,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Column {
                        Text(
                            text = "OMAID KİMLİĞİ",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary,
                            letterSpacing = 0.8.sp
                        )
                        Text(
                            text = "16 Haneli Hesapsız ve Kör Buluşma",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                NetworkStatusBadge(
                    wanStatus = wanStatus,
                    onClick = onNetworkStatusClick
                )
            }

            Spacer(modifier = Modifier.height(14.dp))

            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .clickable(onClick = onCopyId),
                color = MaterialTheme.colorScheme.surfaceContainerHigh,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.6f))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = identity.formattedId,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        fontFamily = JetBrainsMonoFontFamily,
                        color = MaterialTheme.colorScheme.onSurface,
                        letterSpacing = 1.2.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Kör Konu: ${identity.blindTopic.take(16)}...",
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = JetBrainsMonoFontFamily,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                OutlinedButton(
                    onClick = onCopyId,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 2.dp, vertical = 6.dp)
                ) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(3.dp))
                    Text(
                        text = "Kopyala",
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 1
                    )
                }

                OutlinedButton(
                    onClick = onShowQr,
                    modifier = Modifier.weight(0.9f),
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 2.dp, vertical = 6.dp)
                ) {
                    Icon(
                        Icons.Default.QrCode,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(3.dp))
                    Text(
                        text = "QR",
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 1
                    )
                }

                OutlinedButton(
                    onClick = onScanQr,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color(0xFF38BDF8)
                    ),
                    contentPadding = PaddingValues(horizontal = 2.dp, vertical = 6.dp)
                ) {
                    Icon(
                        Icons.Default.QrCodeScanner,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp),
                        tint = Color(0xFF38BDF8)
                    )
                    Spacer(modifier = Modifier.width(3.dp))
                    Text(
                        text = "Tara",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1
                    )
                }

                OutlinedButton(
                    onClick = onEditId,
                    modifier = Modifier.weight(0.9f),
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 2.dp, vertical = 6.dp)
                ) {
                    Icon(
                        Icons.Default.Edit,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(3.dp))
                    Text(
                        text = "Bağla",
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 1
                    )
                }

                OutlinedButton(
                    onClick = onResetId,
                    modifier = Modifier.weight(0.9f),
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 2.dp, vertical = 6.dp)
                ) {
                    Icon(
                        Icons.Default.Refresh,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(3.dp))
                    Text(
                        text = "Sıfırla",
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 1
                    )
                }
            }
        }
    }
}

@Composable
fun NetworkStatusBadge(
    wanStatus: WanStatus,
    onClick: () -> Unit
) {
    val (badgeText, dotColor) = when (wanStatus.mode) {
        NetworkTransportMode.LAN -> Pair("LAN", Color(0xFF10B981))
        NetworkTransportMode.WAN -> Pair(
            if (wanStatus.isWanReachable) "WAN" else "WAN (Hazır)",
            Color(0xFF38BDF8)
        )
        NetworkTransportMode.P2P_MESH -> Pair("P2P MESH", Color(0xFF00E5FF))
    }

    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(10.dp),
        color = dotColor.copy(alpha = 0.15f),
        border = BorderStroke(1.dp, dotColor.copy(alpha = 0.4f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(6.dp)
                    .clip(CircleShape)
                    .background(dotColor)
            )
            Spacer(modifier = Modifier.width(5.dp))
            Text(
                text = badgeText,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = dotColor
            )
        }
    }
}

@Composable
fun OmaIdQrDialog(
    identity: OmaIdentity,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var qrBitmap by remember { mutableStateOf<Bitmap?>(null) }

    LaunchedEffect(identity.formattedId) {
        withContext(Dispatchers.Default) {
            try {
                val writer = QRCodeWriter()
                val qrContent = "omasend://identity/${identity.rawId}"
                val bitMatrix = writer.encode(qrContent, BarcodeFormat.QR_CODE, 512, 512)
                val width = bitMatrix.width
                val height = bitMatrix.height
                val bmp = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
                for (x in 0 until width) {
                    for (y in 0 until height) {
                        bmp.setPixel(
                            x,
                            y,
                            if (bitMatrix.get(x, y)) android.graphics.Color.BLACK else android.graphics.Color.WHITE
                        )
                    }
                }
                qrBitmap = bmp
            } catch (_: Exception) {}
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "OmaID QR Paylaşım",
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (qrBitmap != null) {
                    Image(
                        bitmap = qrBitmap!!.asImageBitmap(),
                        contentDescription = "OmaID QR",
                        modifier = Modifier
                            .size(240.dp)
                            .clip(RoundedCornerShape(16.dp))
                            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(16.dp))
                            .padding(8.dp)
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .size(240.dp)
                            .clip(RoundedCornerShape(16.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                Text(
                    text = identity.formattedId,
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = JetBrainsMonoFontFamily,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = "Bu QR kodu diğer cihazınızdan taratarak veya 16 haneli kimliği girerek kör buluşma ile doğrudan dosya aktarabilirsiniz.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                    val clip = ClipData.newPlainText("OmaID", identity.formattedId)
                    clipboard?.setPrimaryClip(clip)
                    Toast.makeText(context, "OmaID panoya kopyalandı", Toast.LENGTH_SHORT).show()
                }
            ) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text("Kopyala")
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
fun EditOmaIdDialog(
    currentId: String,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit
) {
    var input by remember { mutableStateOf(currentId) }
    val isValid = OmaIdentity.isValid(input)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "P2P Cihaz Kimliği (OmaID)",
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Surface(
                    color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f),
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "GİRİŞ / HESAP GEREKMEZ • P2P",
                        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "OmaSend sunucu kaydı gerektirmeyen anonim bir yerel aktarım aracıdır. Cihazınıza özel 16 haneli P2P eşleşme kimliğini buradan görebilir, değiştirebilir veya rastgele üretebilirsiniz.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Spacer(modifier = Modifier.height(12.dp))

                OutlinedTextField(
                    value = input,
                    onValueChange = { rawNewValue ->
                        val clean = rawNewValue.replace("-", "").replace(" ", "").uppercase().filter { it.isLetterOrDigit() }.take(16)
                        input = if (clean.isEmpty()) "" else clean.chunked(4).joinToString("-")
                    },
                    label = { Text("16 Haneli P2P OmaID") },
                    placeholder = { Text("4829-1048-5729-1104") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = androidx.compose.ui.text.TextStyle(
                        fontFamily = JetBrainsMonoFontFamily,
                        fontWeight = FontWeight.Bold
                    ),
                    isError = input.isNotBlank() && !isValid
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextButton(
                        onClick = { input = OmaIdentity.generate() },
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "Rastgele Yeni Kimlik",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }

                    if (input.isNotBlank()) {
                        if (isValid) {
                            Text(
                                text = "[Luhn mod 10 Doğrulandı]",
                                style = MaterialTheme.typography.labelSmall,
                                color = Color(0xFF10B981)
                            )
                        } else {
                            Text(
                                text = "[Geçersiz Checksum]",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onSave(input) },
                enabled = isValid
            ) {
                Text("Kaydet & Kullan")
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
fun ResetOmaIdConfirmDialog(
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Yeni OmaID Oluşturulsun mu?",
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Text(
                text = "Yeni bir 16 haneli hesapsız kimlik üretildiğinde kör buluşma konunuz değişir. Eski kimliğinizi kullanan eşler yeni kimliğinizi ekleyene kadar doğrudan WAN üzerinden bağlanamaz.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary
                )
            ) {
                Text("Yeni Kimlik Üret")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Vazgeç")
            }
        }
    )
}

@Composable
fun NetworkStatusDialog(
    wanStatus: WanStatus,
    identity: OmaIdentity,
    onDismiss: () -> Unit,
    onSwitchMode: (NetworkTransportMode) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Ağ ve Kör Buluşma Durumu",
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            text = "Ağ Taşıma Modu Seçimi",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            listOf(
                                NetworkTransportMode.LAN to "LAN",
                                NetworkTransportMode.WAN to "WAN",
                                NetworkTransportMode.P2P_MESH to "P2P Mesh"
                            ).forEach { (mode, label) ->
                                val isSelected = wanStatus.mode == mode
                                FilterChip(
                                    selected = isSelected,
                                    onClick = { onSwitchMode(mode) },
                                    label = { Text(label, style = MaterialTheme.typography.labelSmall) }
                                )
                            }
                        }
                    }
                }

                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = "STUN ve Uç Nokta Bilgisi",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "Yerel IP: ${NetworkUtils.getLocalIpAddress()}:53317",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = JetBrainsMonoFontFamily,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Text(
                            text = if (wanStatus.publicIp != null) "Genel WAN IP: ${wanStatus.publicIp}:${wanStatus.publicPort}" else "STUN Keşfi: Aranıyor...",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = JetBrainsMonoFontFamily,
                            color = if (wanStatus.publicIp != null) Color(0xFF10B981) else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "Kör Konu (HMAC):",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = identity.blindTopic,
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = JetBrainsMonoFontFamily,
                            color = MaterialTheme.colorScheme.secondary,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
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


