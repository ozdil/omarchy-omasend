package io.omarchy.omasend

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import io.omarchy.omasend.audio.OmaSoundEngine
import io.omarchy.omasend.crypto.OmaIdentity
import io.omarchy.omasend.network.DiscoveryManager
import io.omarchy.omasend.network.NetworkConnectivityWatcher
import io.omarchy.omasend.network.NetworkTransportMode
import io.omarchy.omasend.network.OmaSendClient
import io.omarchy.omasend.network.OmaSendServer
import io.omarchy.omasend.network.WanDiscoveryEngine
import io.omarchy.omasend.repository.ClipboardVault
import io.omarchy.omasend.ui.haptics.OmaHapticController

class OmaSendApp : Application() {
    lateinit var discoveryManager: DiscoveryManager
        private set
    lateinit var server: OmaSendServer
        private set
    lateinit var client: OmaSendClient
        private set
    lateinit var soundEngine: OmaSoundEngine
        private set
    lateinit var hapticController: OmaHapticController
        private set
    lateinit var clipboardVault: ClipboardVault
        private set
    lateinit var omaIdentity: OmaIdentity
        private set
    lateinit var wanDiscoveryEngine: WanDiscoveryEngine
        private set
    lateinit var networkWatcher: NetworkConnectivityWatcher
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        createNotificationChannels()

        soundEngine = OmaSoundEngine(this)
        hapticController = OmaHapticController(this)
        clipboardVault = ClipboardVault.getInstance(this)
        omaIdentity = OmaIdentity.getOrGenerate(this)
        wanDiscoveryEngine = WanDiscoveryEngine(this, identityProvider = { omaIdentity })

        discoveryManager = DiscoveryManager(this)
        server = OmaSendServer(this).apply {
            getDiscoveryMode = { discoveryManager.discoveryMode.value }
        }
        client = OmaSendClient(this)

        networkWatcher = NetworkConnectivityWatcher(this).apply {
            onLanAvailable = {
                discoveryManager.forceRefresh()
                wanDiscoveryEngine.setNetworkMode(NetworkTransportMode.LAN)
            }
            onCellularAvailable = {
                wanDiscoveryEngine.setNetworkMode(NetworkTransportMode.WAN)
                discoveryManager.forceRefresh()
            }
            onNetworkChanged = { state ->
                if (state.isLanAvailable) {
                    discoveryManager.forceRefresh()
                }
            }
            start()
        }

        server.start()
        discoveryManager.start()
        wanDiscoveryEngine.start()
    }

    fun refreshOmaIdentity(): OmaIdentity {
        omaIdentity = OmaIdentity.getOrGenerate(this)
        return omaIdentity
    }

    fun setCustomOmaIdentity(newOmaId: String): OmaIdentity {
        omaIdentity = OmaIdentity.save(this, newOmaId)
        return omaIdentity
    }

    fun resetOmaIdentity(): OmaIdentity {
        omaIdentity = OmaIdentity.reset(this)
        return omaIdentity
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                CHANNEL_SERVICE,
                "OmaSend Background Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps OmaSend reachable for nearby P2P file and clipboard sharing"
            }

            val transferChannel = NotificationChannel(
                CHANNEL_TRANSFERS,
                "OmaSend Transfers",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifications for incoming and completed file transfers"
                enableVibration(true)
            }

            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(serviceChannel)
            manager.createNotificationChannel(transferChannel)
        }
    }

    override fun onTerminate() {
        super.onTerminate()
        try {
            networkWatcher.stop()
            soundEngine.release()
        } catch (_: Exception) {}
    }

    companion object {
        const val CHANNEL_SERVICE = "omasend_service_channel"
        const val CHANNEL_TRANSFERS = "omasend_transfers_channel"
        const val NOTIFICATION_SERVICE_ID = 1001

        lateinit var instance: OmaSendApp
            private set
    }
}
