package io.omarchy.omasend

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import io.omarchy.omasend.model.IncomingTransferPrompt
import io.omarchy.omasend.network.NetworkUtils
import io.omarchy.omasend.service.OmaSendForegroundService
import io.omarchy.omasend.ui.RadarScreen
import io.omarchy.omasend.ui.theme.OmaSendTheme

class MainActivity : ComponentActivity() {

    private var incomingPrompt by mutableStateOf<IncomingTransferPrompt?>(null)
    private var clipboardListener: ClipboardManager.OnPrimaryClipChangedListener? = null

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { _ ->
        val app = application as? OmaSendApp
        app?.discoveryManager?.forceRefresh()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        val app = application as OmaSendApp

        // Request modern notifications and camera/storage permissions
        checkAndRequestPermissions()

        // Start background service
        OmaSendForegroundService.startService(this)

        // Setup local clipboard tracking
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        clipboardListener = ClipboardManager.OnPrimaryClipChangedListener {
            app.clipboardVault.processLocalClipboard(this, app)
        }
        clipboard?.addPrimaryClipChangedListener(clipboardListener)

        // Wire server callbacks
        app.server.onIncomingTransferPrompt = { prompt ->
            incomingPrompt = prompt
        }

        app.server.onFileReceived = { filename, size ->
            app.soundEngine.playReceiveSound()
            app.hapticController.onFileReceivedImpact()
            Toast.makeText(
                this,
                "Received '$filename' (${NetworkUtils.formatBytes(size)}) saved to Downloads/OmaSend",
                Toast.LENGTH_LONG
            ).show()
        }

        app.server.onClipboardReceived = { senderName, _ ->
            Toast.makeText(this, "Clipboard received from $senderName", Toast.LENGTH_SHORT).show()
        }

        setContent {
            OmaSendTheme {
                RadarScreen(
                    app = app,
                    incomingPrompt = incomingPrompt,
                    onAcceptPrompt = { token ->
                        app.server.acceptTransfer(token)
                        incomingPrompt = null
                        Toast.makeText(this, "Transfer accepted. Receiving...", Toast.LENGTH_SHORT).show()
                    },
                    onDeclinePrompt = { token ->
                        app.server.rejectTransfer(token)
                        incomingPrompt = null
                        Toast.makeText(this, "Transfer declined", Toast.LENGTH_SHORT).show()
                    }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        val app = application as? OmaSendApp
        app?.discoveryManager?.forceRefresh()
        app?.networkWatcher?.forceRefresh()
    }

    private fun checkAndRequestPermissions() {
        val permissions = mutableListOf<String>()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        if (permissions.isNotEmpty()) {
            permissionLauncher.launch(permissions.toTypedArray())
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        clipboardListener?.let {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            clipboard?.removePrimaryClipChangedListener(it)
        }
        val app = application as? OmaSendApp
        app?.discoveryManager?.stop()
        OmaSendForegroundService.stopService(this)
    }
}
