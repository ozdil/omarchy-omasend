package io.omarchy.omasend

import io.omarchy.omasend.network.DiscoveryManager
import org.junit.Assert.assertEquals
import org.junit.Test

class DiscoveryDutyCycleTest {

    @Test
    fun testAdaptiveDutyCycleActivePhase() {
        val t0 = 100_000L
        // When active peers exist, interval should always be 1000ms (1s)
        val intervalWithPeers = DiscoveryManager.calculateAdaptiveInterval(
            lastActiveEventTime = t0,
            hasActivePeers = true,
            currentTimeMs = t0 + 60_000L // even after 60s
        )
        assertEquals(1000L, intervalWithPeers)
        assertEquals(DiscoveryManager.ACTIVE_INTERVAL_MS, intervalWithPeers)
    }

    @Test
    fun testAdaptiveDutyCycleProgressionWhenIdle() {
        val t0 = 100_000L

        // Phase 1: 0s to 9.9s idle -> 1000ms (Active / initial search)
        val tEarly = t0 + 5000L
        val intervalEarly = DiscoveryManager.calculateAdaptiveInterval(
            lastActiveEventTime = t0,
            hasActivePeers = false,
            currentTimeMs = tEarly
        )
        assertEquals(1000L, intervalEarly)

        // Phase 2: 10s to 29.9s idle -> 2000ms (Search Phase)
        val tSearch = t0 + 15000L
        val intervalSearch = DiscoveryManager.calculateAdaptiveInterval(
            lastActiveEventTime = t0,
            hasActivePeers = false,
            currentTimeMs = tSearch
        )
        assertEquals(2000L, intervalSearch)
        assertEquals(DiscoveryManager.SEARCH_INTERVAL_MS, intervalSearch)

        // Phase 3: >= 30s idle -> 6000ms (Deep Idle / Battery saving)
        val tDeepIdle = t0 + 35000L
        val intervalDeepIdle = DiscoveryManager.calculateAdaptiveInterval(
            lastActiveEventTime = t0,
            hasActivePeers = false,
            currentTimeMs = tDeepIdle
        )
        assertEquals(6000L, intervalDeepIdle)
        assertEquals(DiscoveryManager.IDLE_INTERVAL_MS, intervalDeepIdle)
    }

    @Test
    fun testAdaptiveDutyCycleResetOnActiveEvent() {
        val t0 = 100_000L
        val tDeepIdle = t0 + 50_000L // 50s idle -> in 6000ms state

        val beforeReset = DiscoveryManager.calculateAdaptiveInterval(
            lastActiveEventTime = t0,
            hasActivePeers = false,
            currentTimeMs = tDeepIdle
        )
        assertEquals(6000L, beforeReset)

        // Peer detected / refreshed at tDeepIdle
        val afterReset = DiscoveryManager.calculateAdaptiveInterval(
            lastActiveEventTime = tDeepIdle,
            hasActivePeers = false,
            currentTimeMs = tDeepIdle + 100L
        )
        assertEquals(1000L, afterReset)
    }

    @Test
    fun testPeerExpiryTimeoutAlignedWithDutyCycle() {
        // Peer expiry timeout must be 18s (3 missed 6s beacons)
        assertEquals(18000L, DiscoveryManager.PEER_EXPIRY_TIMEOUT_MS)
    }
}
