package io.omarchy.omasend

import io.omarchy.omasend.network.ConnectionType
import io.omarchy.omasend.network.NetworkState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkConnectivityWatcherTest {

    @Test
    fun testNetworkStateDefaults() {
        val defaultState = NetworkState()
        assertFalse(defaultState.isConnected)
        assertEquals(ConnectionType.NONE, defaultState.connectionType)
        assertFalse(defaultState.isLanAvailable)
        assertFalse(defaultState.isMetered)
        assertEquals("127.0.0.1", defaultState.localIp)
    }

    @Test
    fun testLanWifiState() {
        val wifiState = NetworkState(
            isConnected = true,
            connectionType = ConnectionType.WIFI,
            isLanAvailable = true,
            isMetered = false,
            localIp = "192.168.1.50"
        )
        assertTrue(wifiState.isConnected)
        assertEquals(ConnectionType.WIFI, wifiState.connectionType)
        assertTrue(wifiState.isLanAvailable)
        assertFalse(wifiState.isMetered)
        assertEquals("192.168.1.50", wifiState.localIp)
    }

    @Test
    fun testCellularWanState() {
        val cellularState = NetworkState(
            isConnected = true,
            connectionType = ConnectionType.CELLULAR,
            isLanAvailable = false,
            isMetered = true,
            localIp = "10.45.12.8"
        )
        assertTrue(cellularState.isConnected)
        assertEquals(ConnectionType.CELLULAR, cellularState.connectionType)
        assertFalse(cellularState.isLanAvailable)
        assertTrue(cellularState.isMetered)
    }
}
