package io.omarchy.omasend

import io.omarchy.omasend.network.TransferSpeedCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransferSpeedCalculatorTest {

    @Test
    fun testInitialMetricsCalculation() {
        val totalBytes = 100L * 1024L * 1024L // 100 MiB
        val calc = TransferSpeedCalculator(totalBytes)

        val metrics = calc.update(0L, currentTimeMs = 1000L)
        assertEquals(0L, metrics.bytesTransferred)
        assertEquals(totalBytes, metrics.totalBytes)
        assertEquals(0, metrics.percent)
        assertEquals(0.0, metrics.speedMBps, 0.001)
        assertEquals(0L, metrics.etaSeconds)
        assertFalse(metrics.isCompleted)
    }

    @Test
    fun testThroughputAndEtaProgression() {
        val totalBytes = 100L * 1024L * 1024L // 100 MiB
        val calc = TransferSpeedCalculator(totalBytes, smoothingFactor = 0.5)

        // 0s: start at t=1000ms
        calc.update(0L, currentTimeMs = 1000L)

        // 1s later: 10 MiB transferred -> ~10 MB/s
        val transferred10MiB = 10L * 1024L * 1024L
        val m1 = calc.update(transferred10MiB, currentTimeMs = 2000L)

        assertEquals(10, m1.percent)
        assertTrue("Speed should be ~10 MB/s", m1.speedMBps in 9.5..10.5)
        assertTrue("ETA should be ~9 seconds for remaining 90 MiB", m1.etaSeconds in 8L..10L)
        assertFalse(m1.isCompleted)

        // 2s later (t=3000ms): 30 MiB transferred total (20 MiB in this 1s step)
        val transferred30MiB = 30L * 1024L * 1024L
        val m2 = calc.update(transferred30MiB, currentTimeMs = 3000L)

        assertEquals(30, m2.percent)
        assertTrue("Smoothed speed should reflect accelerated rate", m2.speedMBps > 12.0)
        assertTrue("ETA should be bounded for remaining 70 MiB", m2.etaSeconds in 3L..7L)
        assertFalse(m2.isCompleted)

        // Completion at t=5000ms: 100 MiB transferred
        val mFinal = calc.update(totalBytes, currentTimeMs = 5000L)
        assertEquals(100, mFinal.percent)
        assertEquals(0L, mFinal.etaSeconds)
        assertTrue(mFinal.isCompleted)
    }

    @Test
    fun testPercentageClamping() {
        val calc = TransferSpeedCalculator(1000L)
        val overflow = calc.update(2000L, currentTimeMs = 2000L)
        assertEquals(100, overflow.percent)
        assertTrue(overflow.isCompleted)

        val calcZero = TransferSpeedCalculator(0L)
        val zeroMetrics = calcZero.update(0L)
        assertEquals(0, zeroMetrics.percent)
        assertFalse(zeroMetrics.isCompleted)
    }

    @Test
    fun testResetFunctionality() {
        val totalBytes = 50L * 1024L * 1024L
        val calc = TransferSpeedCalculator(totalBytes)

        calc.update(25L * 1024L * 1024L, currentTimeMs = 2000L)
        calc.reset(currentTimeMs = 3000L)

        val freshMetrics = calc.update(10L * 1024L * 1024L, currentTimeMs = 4000L)
        assertEquals(10L * 1024L * 1024L, freshMetrics.bytesTransferred)
        assertEquals(20, freshMetrics.percent)
    }
}
