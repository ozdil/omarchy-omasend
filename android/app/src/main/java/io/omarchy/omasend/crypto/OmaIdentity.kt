package io.omarchy.omasend.crypto

import android.content.Context
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.Serializable

@Serializable
data class OmaIdentity(
    val formattedId: String,
    val createdAt: Long = System.currentTimeMillis()
) {
    val rawId: String
        get() = unformat(formattedId)

    val blindTopic: String
        get() = deriveBlindTopic(formattedId)

    companion object {
        private const val PREFS_NAME = "omasend_identity_store"
        private const val KEY_OMA_ID = "active_oma_id"
        private const val KEY_CREATED_AT = "oma_id_created_at"
        private const val DEFAULT_SALT = "omasend-gh-rendezvous-v1"
        private const val KEY_DERIVATION_SALT = ":omasend-e2ee-key-v1"

        /**
         * Validates a 16-digit OmaID using Luhn mod 10 checksum.
         * Case-insensitive and supports formatted or unformatted inputs.
         */
        fun isValid(input: String?): Boolean {
            if (input.isNullOrBlank()) return false
            val clean = unformat(input)
            if (clean.length != 16) return false
            if (!clean.all { it.isDigit() }) return false

            var sum = 0
            for (i in 0 until 16) {
                val digit = clean[i].digitToInt()
                if (i % 2 == 0) {
                    val doubled = digit * 2
                    sum += if (doubled > 9) doubled - 9 else doubled
                } else {
                    sum += digit
                }
            }
            return sum % 10 == 0
        }

        /**
         * Parses and formats any case-insensitive or unformatted OmaID input.
         * Returns OmaIdentity instance if valid, null otherwise.
         */
        fun parse(input: String?): OmaIdentity? {
            if (!isValid(input)) return null
            return OmaIdentity(format(input!!))
        }

        /**
         * Generates a random 16-digit OmaID satisfying Luhn mod 10.
         */
        fun generateRandomOmaId(): String {
            val random = SecureRandom()
            val digits = IntArray(16)
            var sum = 0
            for (i in 0 until 15) {
                digits[i] = random.nextInt(10)
                if (i % 2 == 0) {
                    val doubled = digits[i] * 2
                    sum += if (doubled > 9) doubled - 9 else doubled
                } else {
                    sum += digits[i]
                }
            }
            val checkDigit = (10 - (sum % 10)) % 10
            digits[15] = checkDigit
            val raw = digits.joinToString("")
            return format(raw)
        }

        /**
         * Formats raw digits into XXXX-XXXX-XXXX-XXXX format.
         */
        fun format(raw: String): String {
            val clean = unformat(raw)
            if (clean.isEmpty()) return ""
            return clean.chunked(4).joinToString("-")
        }

        /**
         * Removes spaces and hyphens from OmaID and normalizes to uppercase.
         */
        fun unformat(formatted: String): String {
            return formatted.replace("-", "").replace(" ", "").trim().uppercase()
        }

        /**
         * Derives a 64-character hex blind rendezvous topic using HMAC-SHA256.
         */
        fun deriveBlindTopic(omaId: String, salt: String = DEFAULT_SALT): String {
            val raw = unformat(omaId)
            val mac = Mac.getInstance("HmacSHA256")
            val secretKey = SecretKeySpec(raw.toByteArray(Charsets.UTF_8), "HmacSHA256")
            mac.init(secretKey)
            val hmacBytes = mac.doFinal(salt.toByteArray(Charsets.UTF_8))
            return hmacBytes.joinToString("") { "%02x".format(it) }
        }

        /**
         * Derives a 256-bit AES key from OmaID.
         */
        fun deriveAesKey(omaId: String): SecretKeySpec {
            val raw = unformat(omaId)
            val md = MessageDigest.getInstance("SHA-256")
            val keyBytes = md.digest((raw + KEY_DERIVATION_SALT).toByteArray(Charsets.UTF_8))
            return SecretKeySpec(keyBytes, "AES")
        }

        /**
         * Encrypts binary payload using AES-256-GCM.
         * Output layout: [12-byte IV] + [Ciphertext with 128-bit Auth Tag]
         */
        fun encryptPayload(plaintext: ByteArray, omaId: String, aad: ByteArray? = null): ByteArray {
            val key = deriveAesKey(omaId)
            val iv = ByteArray(12)
            SecureRandom().nextBytes(iv)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            if (aad != null) {
                cipher.updateAAD(aad)
            }
            val ciphertext = cipher.doFinal(plaintext)
            val output = ByteArray(iv.size + ciphertext.size)
            System.arraycopy(iv, 0, output, 0, iv.size)
            System.arraycopy(ciphertext, 0, output, iv.size, ciphertext.size)
            return output
        }

        /**
         * Decrypts binary payload using AES-256-GCM.
         */
        fun decryptPayload(ciphertextWithIv: ByteArray, omaId: String, aad: ByteArray? = null): ByteArray {
            if (ciphertextWithIv.size < 28) {
                throw IllegalArgumentException("Ciphertext payload too short for AES-GCM")
            }
            val key = deriveAesKey(omaId)
            val iv = ciphertextWithIv.copyOfRange(0, 12)
            val ciphertext = ciphertextWithIv.copyOfRange(12, ciphertextWithIv.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            if (aad != null) {
                cipher.updateAAD(aad)
            }
            return cipher.doFinal(ciphertext)
        }

        /**
         * String helper: Encrypts plaintext string to Base64 AES-256-GCM.
         */
        fun encryptString(plaintext: String, omaId: String): String {
            val encrypted = encryptPayload(plaintext.toByteArray(Charsets.UTF_8), omaId)
            return Base64.getEncoder().encodeToString(encrypted)
        }

        /**
         * String helper: Decrypts Base64 AES-256-GCM ciphertext to plaintext string.
         */
        fun decryptString(encryptedBase64: String, omaId: String): String {
            val bytes = Base64.getDecoder().decode(encryptedBase64)
            val decrypted = decryptPayload(bytes, omaId)
            return String(decrypted, Charsets.UTF_8)
        }

        /**
         * Gets stored identity or generates a new one.
         */
        fun getOrGenerate(context: Context): OmaIdentity {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val storedId = prefs.getString(KEY_OMA_ID, null)
            val createdAt = prefs.getLong(KEY_CREATED_AT, 0L)

            if (storedId != null && isValid(storedId)) {
                return OmaIdentity(format(storedId), if (createdAt > 0L) createdAt else System.currentTimeMillis())
            }

            val newId = generateRandomOmaId()
            val now = System.currentTimeMillis()
            prefs.edit()
                .putString(KEY_OMA_ID, unformat(newId))
                .putLong(KEY_CREATED_AT, now)
                .apply()
            return OmaIdentity(newId, now)
        }

        /**
         * Saves a custom OmaID if valid.
         */
        fun save(context: Context, omaId: String): OmaIdentity {
            if (!isValid(omaId)) {
                throw IllegalArgumentException("Geçersiz 16 haneli OmaID formatı veya Luhn sağlama hatası")
            }
            val formatted = format(omaId)
            val now = System.currentTimeMillis()
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit()
                .putString(KEY_OMA_ID, unformat(formatted))
                .putLong(KEY_CREATED_AT, now)
                .apply()
            return OmaIdentity(formatted, now)
        }

        /**
         * Resets and generates a fresh OmaID.
         */
        fun reset(context: Context): OmaIdentity {
            val newId = generateRandomOmaId()
            val now = System.currentTimeMillis()
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit()
                .putString(KEY_OMA_ID, unformat(newId))
                .putLong(KEY_CREATED_AT, now)
                .apply()
            return OmaIdentity(newId, now)
        }
    }
}
