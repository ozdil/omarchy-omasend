package io.omarchy.omasend

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import io.omarchy.omasend.network.DiscoveryManager
import io.omarchy.omasend.network.OmaSendClient
import io.omarchy.omasend.network.OmaSendServer

class OmaSendApp : Application() {
    lateinit var discoveryManager: DiscoveryManager
        private set
    lateinit var server: OmaSendServer
        private set
    lateinit var client: OmaSendClient
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        createNotificationChannels()

        discoveryManager = DiscoveryManager(this)
        server = OmaSendServer(this)
        client = OmaSendClient(this)

        server.start()
        discoveryManager.start()
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

    companion object {
        const val CHANNEL_SERVICE = "omasend_service_channel"
        const val CHANNEL_TRANSFERS = "omasend_transfers_channel"
        const val NOTIFICATION_SERVICE_ID = 1001

        lateinit var instance: OmaSendApp
            private set
    }
}
