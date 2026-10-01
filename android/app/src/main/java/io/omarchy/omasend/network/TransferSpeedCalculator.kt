package io.omarchy.omasend.network

import io.omarchy.omasend.model.TransferMetrics

/**
 * TransferSpeedCalculator
 *
 * Implements an Exponential Moving Average (EMA) smoothed transfer rate and ETA estimator
 * based on ACM SIGCOMM streaming principles.
 *
 * Prevents instantaneous throughput jitter while providing accurate remaining time estimates.
 */
class TransferSpeedCalculator(
    private val totalBytes: Long,
    private val smoothingFactor: Double = 0.3
) {
    private var startTimeMs: Long = -1L
    private var lastSampleTimeMs: Long = -1L
    private var lastSampleBytes: Long = 0L
    private var smoothedBytesPerSec: Double = 0.0

    @Synchronized
    fun update(bytesTransferred: Long, currentTimeMs: Long = System.currentTimeMillis()): TransferMetrics {
        val now = currentTimeMs
        if (startTimeMs == -1L) {
            startTimeMs = now
            lastSampleTimeMs = now
        }
        val deltaMs = now - lastSampleTimeMs
        val totalElapsedMs = maxOf(1L, now - startTimeMs)

        if (deltaMs >= 150L || bytesTransferred >= totalBytes) {
            val deltaBytes = bytesTransferred - lastSampleBytes
            if (deltaMs > 0 && deltaBytes >= 0) {
                val instantaneousRate = (deltaBytes.toDouble() / deltaMs.toDouble()) * 1000.0
                smoothedBytesPerSec = if (smoothedBytesPerSec <= 0.0) {
                    instantaneousRate
                } else {
                    (smoothingFactor * instantaneousRate) + ((1.0 - smoothingFactor) * smoothedBytesPerSec)
                }
            }
            lastSampleTimeMs = now
            lastSampleBytes = bytesTransferred
        }

        val effectiveRate = if (smoothedBytesPerSec > 0.0) {
            smoothedBytesPerSec
        } else {
            (bytesTransferred.toDouble() / totalElapsedMs.toDouble()) * 1000.0
        }

        val speedMBps = (effectiveRate / (1024.0 * 1024.0)).coerceAtLeast(0.0)
        val remainingBytes = maxOf(0L, totalBytes - bytesTransferred)
        val etaSeconds = if (effectiveRate > 1024.0 && remainingBytes > 0) {
            (remainingBytes / effectiveRate).toLong().coerceAtLeast(1L)
        } else {
            0L
        }
        val percent = if (totalBytes > 0) {
            ((bytesTransferred * 100) / totalBytes).toInt().coerceIn(0, 100)
        } else {
            0
        }

        return TransferMetrics(
            bytesTransferred = bytesTransferred,
            totalBytes = totalBytes,
            percent = percent,
            speedMBps = speedMBps,
            etaSeconds = etaSeconds,
            isCompleted = totalBytes > 0 && bytesTransferred >= totalBytes
        )
    }

    @Synchronized
    fun reset(currentTimeMs: Long = System.currentTimeMillis()) {
        startTimeMs = currentTimeMs
        lastSampleTimeMs = currentTimeMs
        lastSampleBytes = 0L
        smoothedBytesPerSec = 0.0
    }
}
