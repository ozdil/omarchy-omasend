package io.omarchy.omasend.audio

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.SoundPool
import io.omarchy.omasend.R

class OmaSoundEngine(private val context: Context) {

    private val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
    private var soundPool: SoundPool? = null

    private var soundIdSend: Int = 0
    private var soundIdReceive: Int = 0
    private var isLoaded: Boolean = false

    init {
        initSoundPool()
    }

    private fun initSoundPool() {
        val audioAttributes = AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_ASSISTANCE_SONIFICATION)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()

        soundPool = SoundPool.Builder()
            .setMaxStreams(4)
            .setAudioAttributes(audioAttributes)
            .build()

        soundPool?.setOnLoadCompleteListener { _, _, status ->
            if (status == 0) {
                isLoaded = true
            }
        }

        soundPool?.let { pool ->
            soundIdSend = pool.load(context, R.raw.send_whoosh, 1)
            soundIdReceive = pool.load(context, R.raw.receive_whoosh, 1)
        }
    }

    /**
     * Plays the forward whoosh sound when a file is dispatched from the Android device.
     */
    fun playSendSound() {
        playSound(soundIdSend, volume = 0.9f)
    }

    /**
     * Plays the inverted whoosh sound (receive_whoosh.wav) when a file lands on the Android device.
     */
    fun playReceiveSound() {
        playSound(soundIdReceive, volume = 1.0f)
    }

    private fun playSound(soundId: Int, volume: Float) {
        if (!isLoaded || soundId == 0) return

        val ringerMode = audioManager?.ringerMode ?: AudioManager.RINGER_MODE_NORMAL
        if (ringerMode != AudioManager.RINGER_MODE_NORMAL) {
            return
        }

        try {
            soundPool?.play(
                soundId,
                volume,
                volume,
                1,
                0,
                1.0f
            )
        } catch (_: Exception) {}
    }

    fun release() {
        try {
            soundPool?.release()
            soundPool = null
            isLoaded = false
        } catch (_: Exception) {}
    }
}
