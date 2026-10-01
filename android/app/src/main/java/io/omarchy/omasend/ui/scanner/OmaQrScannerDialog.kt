package io.omarchy.omasend.ui.scanner

import android.Manifest
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.graphics.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import io.omarchy.omasend.crypto.OmaIdentity
import io.omarchy.omasend.engine.GalleryQrDecoder
import io.omarchy.omasend.engine.OmaIdQrAnalyzer
import io.omarchy.omasend.ui.haptics.OmaHapticController
import io.omarchy.omasend.ui.theme.*
import kotlinx.coroutines.launch
import java.util.concurrent.Executors

@Composable
fun OmaQrScannerDialog(
    onDismissRequest: () -> Unit,
    onOmaIdConnected: (String) -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()

    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        )
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
        if (!granted) {
            Toast.makeText(context, "Kamera izni reddedildi. Galeriden secim yapabilirsiniz.", Toast.LENGTH_SHORT).show()
        }
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    var cameraInstance by remember { mutableStateOf<Camera?>(null) }
    var isFlashOn by remember { mutableStateOf(false) }
    var detectedOmaId by remember { mutableStateOf<String?>(null) }
    var isScanningActive by remember { mutableStateOf(true) }

    val analyzer = remember {
        OmaIdQrAnalyzer { id ->
            if (isScanningActive && detectedOmaId == null) {
                detectedOmaId = id
                isScanningActive = false
                OmaHapticController(context).onClipboardReceived()
            }
        }
    }

    val galleryPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            scope.launch {
                val result = GalleryQrDecoder.decodeOmaIdFromUri(context, uri)
                result.onSuccess { id ->
                    detectedOmaId = id
                    isScanningActive = false
                    OmaHapticController(context).onClipboardReceived()
                }.onFailure {
                    Toast.makeText(context, "Gorselde gecerli OmaID QR kodu bulunamadi", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    Dialog(
        onDismissRequest = {
            cameraInstance?.cameraControl?.enableTorch(false)
            onDismissRequest()
        },
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnBackPress = true,
            dismissOnClickOutside = false
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black)
        ) {
            // 1. Camera Preview
            if (hasCameraPermission) {
                AndroidView(
                    modifier = Modifier.fillMaxSize(),
                    factory = { ctx ->
                        val previewView = PreviewView(ctx).apply {
                            layoutParams = ViewGroup.LayoutParams(
                                ViewGroup.LayoutParams.MATCH_PARENT,
                                ViewGroup.LayoutParams.MATCH_PARENT
                            )
                            scaleType = PreviewView.ScaleType.FILL_CENTER
                        }

                        val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                        cameraProviderFuture.addListener({
                            val cameraProvider = cameraProviderFuture.get()
                            val preview = Preview.Builder().build().also {
                                it.surfaceProvider = previewView.surfaceProvider
                            }

                            val imageAnalysis = ImageAnalysis.Builder()
                                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                                .build()
                                .also {
                                    it.setAnalyzer(Executors.newSingleThreadExecutor(), analyzer)
                                }

                            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

                            try {
                                cameraProvider.unbindAll()
                                cameraInstance = cameraProvider.bindToLifecycle(
                                    lifecycleOwner,
                                    cameraSelector,
                                    preview,
                                    imageAnalysis
                                )
                            } catch (_: Exception) {
                                // Camera binding fallback
                            }
                        }, ContextCompat.getMainExecutor(ctx))

                        previewView
                    }
                )
            } else {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(Color(0xFF0F172A)),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.padding(24.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.CameraAlt,
                            contentDescription = null,
                            tint = Color(0xFF64748B),
                            modifier = Modifier.size(64.dp)
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = "Kamera Iznine Ihtiyac Var",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "OmaID QR kodunu taramak icin kamera izni verin veya galeriden bir gorsel secin.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color(0xFF94A3B8),
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                        Spacer(modifier = Modifier.height(20.dp))
                        Button(
                            onClick = { permissionLauncher.launch(Manifest.permission.CAMERA) },
                            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
                        ) {
                            Text("Kamera Iznini Ver")
                        }
                    }
                }
            }

            // 2. Viewfinder Overlay
            OmaQrScannerViewfinder(
                modifier = Modifier.fillMaxSize(),
                isSuccess = detectedOmaId != null,
                isFlashOn = isFlashOn,
                onFlashToggle = {
                    val nextFlash = !isFlashOn
                    isFlashOn = nextFlash
                    cameraInstance?.cameraControl?.enableTorch(nextFlash)
                    OmaHapticController(context).onClipTick()
                },
                onPickFromGallery = {
                    galleryPickerLauncher.launch("image/*")
                },
                onPasteFromClipboard = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                    val clip = clipboard?.primaryClip
                    if (clip != null && clip.itemCount > 0) {
                        val text = clip.getItemAt(0).text?.toString() ?: ""
                        val parsed = GalleryQrDecoder.parseOmaIdFromScannedPayload(text)
                        if (parsed != null) {
                            detectedOmaId = parsed
                            isScanningActive = false
                            OmaHapticController(context).onClipboardReceived()
                        } else {
                            Toast.makeText(context, "Panoda gecerli 16 haneli OmaID bulunamadi", Toast.LENGTH_SHORT).show()
                        }
                    } else {
                        Toast.makeText(context, "Pano bos", Toast.LENGTH_SHORT).show()
                    }
                },
                onClose = {
                    cameraInstance?.cameraControl?.enableTorch(false)
                    onDismissRequest()
                }
            )

            // 3. Detected OmaID Card (Slide Up from Bottom)
            AnimatedVisibility(
                visible = detectedOmaId != null,
                enter = slideInVertically(initialOffsetY = { it }) + fadeIn(),
                exit = slideOutVertically(targetOffsetY = { it }) + fadeOut(),
                modifier = Modifier.align(Alignment.BottomCenter)
            ) {
                if (detectedOmaId != null) {
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .navigationBarsPadding()
                            .padding(16.dp),
                        shape = RoundedCornerShape(20.dp),
                        color = Color(0xFF0F172A).copy(alpha = 0.95f),
                        border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF10B981))
                    ) {
                        Column(
                            modifier = Modifier.padding(20.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(10.dp)
                                        .clip(CircleShape)
                                        .background(Color(0xFF10B981))
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "OmaID Dogrulandi",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF10B981)
                                )
                            }

                            Spacer(modifier = Modifier.height(12.dp))

                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = Color(0xFF1E293B),
                                border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF334155))
                            ) {
                                Text(
                                    text = detectedOmaId!!,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp,
                                    color = Color(0xFF38BDF8),
                                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
                                    letterSpacing = 2.sp
                                )
                            }

                            Spacer(modifier = Modifier.height(20.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                OutlinedButton(
                                    onClick = {
                                        detectedOmaId = null
                                        isScanningActive = true
                                        analyzer.resume()
                                    },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp)
                                ) {
                                    Text("Tekrar Tara")
                                }

                                Button(
                                    onClick = {
                                        cameraInstance?.cameraControl?.enableTorch(false)
                                        onOmaIdConnected(detectedOmaId!!)
                                    },
                                    modifier = Modifier.weight(1.5f),
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                                    shape = RoundedCornerShape(12.dp)
                                ) {
                                    Icon(Icons.Default.Link, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Cihaza Baglan", fontWeight = FontWeight.Bold, color = Color.Black)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun OmaQrScannerViewfinder(
    modifier: Modifier = Modifier,
    isSuccess: Boolean = false,
    isFlashOn: Boolean = false,
    onFlashToggle: () -> Unit = {},
    onPickFromGallery: () -> Unit = {},
    onPasteFromClipboard: () -> Unit = {},
    onClose: () -> Unit = {}
) {
    val density = LocalDensity.current
    val boxSize = 250.dp
    val boxSizePx = with(density) { boxSize.toPx() }
    val cornerRadiusPx = with(density) { 16.dp.toPx() }
    val cornerLengthPx = with(density) { 32.dp.toPx() }
    val strokeWidthPx = with(density) { 3.5.dp.toPx() }

    val infiniteTransition = rememberInfiniteTransition(label = "LaserScan")
    val laserProgress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "LaserProgress"
    )

    val primaryAccent = if (isSuccess) Color(0xFF10B981) else Color(0xFF38BDF8)
    val secondaryAccent = if (isSuccess) Color(0xFF059669) else Color(0xFF0284C7)

    Box(modifier = modifier.fillMaxSize()) {
        // 1. Canvas Mask & Corner Accents
        Canvas(modifier = Modifier.fillMaxSize()) {
            val canvasWidth = size.width
            val canvasHeight = size.height
            val left = (canvasWidth - boxSizePx) / 2f
            val top = (canvasHeight - boxSizePx) / 2.3f
            val right = left + boxSizePx
            val bottom = top + boxSizePx

            // PorterDuff Cutout
            val path = Path().apply {
                addRect(Rect(0f, 0f, canvasWidth, canvasHeight))
                addRoundRect(
                    RoundRect(
                        rect = Rect(left, top, right, bottom),
                        cornerRadius = CornerRadius(cornerRadiusPx, cornerRadiusPx)
                    )
                )
                fillType = PathFillType.EvenOdd
            }
            drawPath(path = path, color = Color(0xAA020617))

            // 4 Corner Accents
            val cornerBrush = Brush.linearGradient(
                colors = listOf(primaryAccent, secondaryAccent),
                start = Offset(left, top),
                end = Offset(right, bottom)
            )

            // Top-Left
            drawLine(cornerBrush, Offset(left, top + cornerLengthPx), Offset(left, top + cornerRadiusPx), strokeWidthPx)
            drawLine(cornerBrush, Offset(left + cornerRadiusPx, top), Offset(left + cornerLengthPx, top), strokeWidthPx)

            // Top-Right
            drawLine(cornerBrush, Offset(right - cornerLengthPx, top), Offset(right - cornerRadiusPx, top), strokeWidthPx)
            drawLine(cornerBrush, Offset(right, top + cornerRadiusPx), Offset(right, top + cornerLengthPx), strokeWidthPx)

            // Bottom-Left
            drawLine(cornerBrush, Offset(left, bottom - cornerLengthPx), Offset(left, bottom - cornerRadiusPx), strokeWidthPx)
            drawLine(cornerBrush, Offset(left + cornerRadiusPx, bottom), Offset(left + cornerLengthPx, bottom), strokeWidthPx)

            // Bottom-Right
            drawLine(cornerBrush, Offset(right - cornerLengthPx, bottom), Offset(right - cornerRadiusPx, bottom), strokeWidthPx)
            drawLine(cornerBrush, Offset(right, bottom - cornerRadiusPx), Offset(right, bottom - cornerLengthPx), strokeWidthPx)

            // Laser Scan Line
            if (!isSuccess) {
                val currentLaserY = top + (boxSizePx * laserProgress)
                val laserBrush = Brush.horizontalGradient(
                    colors = listOf(
                        Color.Transparent,
                        primaryAccent.copy(alpha = 0.85f),
                        primaryAccent,
                        primaryAccent.copy(alpha = 0.85f),
                        Color.Transparent
                    ),
                    startX = left,
                    endX = right
                )
                drawLine(
                    brush = laserBrush,
                    start = Offset(left + 8f, currentLaserY),
                    end = Offset(right - 8f, currentLaserY),
                    strokeWidth = 3.dp.toPx()
                )
            }
        }

        // 2. Top Bar Controls
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .statusBarsPadding()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = onClose,
                modifier = Modifier.background(Color(0xFF1E293B).copy(alpha = 0.85f), CircleShape)
            ) {
                Icon(Icons.Default.Close, contentDescription = "Kapat", tint = Color.White)
            }

            Surface(
                shape = RoundedCornerShape(20.dp),
                color = Color(0xFF0F172A).copy(alpha = 0.85f),
                border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF334155))
            ) {
                Text(
                    text = "OMAID TARA",
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    letterSpacing = 1.5.sp,
                    color = Color.White,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp)
                )
            }

            IconButton(
                onClick = onFlashToggle,
                modifier = Modifier.background(
                    if (isFlashOn) Color(0xFF38BDF8).copy(alpha = 0.35f) else Color(0xFF1E293B).copy(alpha = 0.85f),
                    CircleShape
                )
            ) {
                Icon(
                    imageVector = if (isFlashOn) Icons.Default.FlashOn else Icons.Default.FlashOff,
                    contentDescription = "Flas",
                    tint = if (isFlashOn) Color(0xFF38BDF8) else Color(0xFF94A3B8)
                )
            }
        }

        // 3. Bottom Action Buttons
        if (!isSuccess) {
            Row(
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .navigationBarsPadding()
                    .padding(bottom = 32.dp, start = 20.dp, end = 20.dp)
                    .fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterHorizontally)
            ) {
                OutlinedButton(
                    onClick = onPickFromGallery,
                    colors = ButtonDefaults.outlinedButtonColors(
                        containerColor = Color(0xFF0F172A).copy(alpha = 0.85f),
                        contentColor = Color.White
                    ),
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF334155))
                ) {
                    Icon(Icons.Default.Image, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Galeriden Sec", fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                }

                OutlinedButton(
                    onClick = onPasteFromClipboard,
                    colors = ButtonDefaults.outlinedButtonColors(
                        containerColor = Color(0xFF0F172A).copy(alpha = 0.85f),
                        contentColor = Color(0xFF38BDF8)
                    ),
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF0284C7))
                ) {
                    Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Panodan Al", fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                }
            }
        }
    }
}
