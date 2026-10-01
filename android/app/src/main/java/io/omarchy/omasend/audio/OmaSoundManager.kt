package io.omarchy.omasend.audio

import android.content.Context
import android.media.AudioAttributes
import android.media.SoundPool
import io.omarchy.omasend.R
import java.util.concurrent.atomic.AtomicBoolean

class OmaSoundManager private constructor(context: Context) {

    private val appContext = context.applicationContext
    private val soundPool: SoundPool
    private var receiveSoundId: Int = 0
    private var sendSoundId: Int = 0
    private val receiveLoaded = AtomicBoolean(false)
    private val sendLoaded = AtomicBoolean(false)

    init {
        val audioAttributes = AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_ASSISTANCE_SONIFICATION)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()

        soundPool = SoundPool.Builder()
            .setMaxStreams(4)
            .setAudioAttributes(audioAttributes)
            .build()

        soundPool.setOnLoadCompleteListener { _, sampleId, status ->
            if (status == 0) {
                if (sampleId == receiveSoundId) receiveLoaded.set(true)
                if (sampleId == sendSoundId) sendLoaded.set(true)
            }
        }

        try {
            receiveSoundId = soundPool.load(appContext, R.raw.receive_whoosh, 1)
            sendSoundId = soundPool.load(appContext, R.raw.send_whoosh, 1)
        } catch (_: Exception) {}
    }

    /**
     * Plays the inverted whoosh sound when a file lands/is received on the Android device.
     */
    fun playReceiveWhoosh() {
        try {
            if (receiveLoaded.get() && receiveSoundId != 0) {
                soundPool.play(receiveSoundId, 1.0f, 1.0f, 1, 0, 1.0f)
            }
        } catch (_: Exception) {}
    }

    /**
     * Plays the forward whoosh sound when a file is dispatched from the Android device.
     */
    fun playSendWhoosh() {
        try {
            if (sendLoaded.get() && sendSoundId != 0) {
                soundPool.play(sendSoundId, 1.0f, 1.0f, 1, 0, 1.0f)
            }
        } catch (_: Exception) {}
    }

    fun release() {
        try {
            soundPool.release()
        } catch (_: Exception) {}
    }

    companion object {
        @Volatile
        private var INSTANCE: OmaSoundManager? = null

        fun getInstance(context: Context): OmaSoundManager {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: OmaSoundManager(context).also { INSTANCE = it }
            }
        }
    }
}
