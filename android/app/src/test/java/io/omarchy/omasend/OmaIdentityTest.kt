package io.omarchy.omasend

import io.omarchy.omasend.crypto.OmaIdentity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.AEADBadTagException

class OmaIdentityTest {

    @Test
    fun testLuhnMod10ValidationValidIds() {
        // Generating known valid IDs through generator
        for (i in 0 until 50) {
            val randomId = OmaIdentity.generateRandomOmaId()
            assertTrue("Generated OmaID should be valid: $randomId", OmaIdentity.isValid(randomId))
            assertTrue("Unformatted OmaID should be valid: ${OmaIdentity.unformat(randomId)}", OmaIdentity.isValid(OmaIdentity.unformat(randomId)))
        }
    }

    @Test
    fun testLuhnMod10ValidationInvalidChecksums() {
        val validId = OmaIdentity.generateRandomOmaId()
        val raw = OmaIdentity.unformat(validId)

        // Mutate the check digit
        val lastDigit = raw.last().digitToInt()
        val mutatedDigit = (lastDigit + 1) % 10
        val invalidId = raw.substring(0, 15) + mutatedDigit

        assertFalse("Mutated check digit should fail Luhn validation", OmaIdentity.isValid(invalidId))
    }

    @Test
    fun testLuhnMod10ValidationInvalidLengthAndCharacters() {
        assertFalse("Empty string should be invalid", OmaIdentity.isValid(""))
        assertFalse("Null string should be invalid", OmaIdentity.isValid(null))
        assertFalse("15 digits should be invalid", OmaIdentity.isValid("123456789012345"))
        assertFalse("17 digits should be invalid", OmaIdentity.isValid("12345678901234567"))
        assertFalse("Non-numeric characters should be invalid", OmaIdentity.isValid("4829-1048-ABCD-1104"))
        assertFalse("Special characters should be invalid", OmaIdentity.isValid("4829-1048-5729-110@"))
    }

    @Test
    fun testOmaIdFormattingAndUnformatting() {
        val raw = "1234567890123456"
        val formatted = OmaIdentity.format(raw)
        assertEquals("1234-5678-9012-3456", formatted)

        val unformatted = OmaIdentity.unformat(formatted)
        assertEquals(raw, unformatted)

        val spaced = "1234 5678 9012 3456"
        assertEquals(raw, OmaIdentity.unformat(spaced))

        val mixedCase = "1234-abcd-5678-efgh"
        assertEquals("1234ABCD5678EFGH", OmaIdentity.unformat(mixedCase))
    }

    @Test
    fun testParseAndCaseInsensitiveValidation() {
        val validId = OmaIdentity.generateRandomOmaId()
        val raw = OmaIdentity.unformat(validId)

        // Parse with hyphens
        val parsed1 = OmaIdentity.parse(validId)
        assertNotNull(parsed1)
        assertEquals(validId, parsed1?.formattedId)

        // Parse without hyphens
        val parsed2 = OmaIdentity.parse(raw)
        assertNotNull(parsed2)
        assertEquals(validId, parsed2?.formattedId)

        // Parse with spaces
        val spaced = raw.chunked(4).joinToString(" ")
        val parsed3 = OmaIdentity.parse(spaced)
        assertNotNull(parsed3)
        assertEquals(validId, parsed3?.formattedId)

        // Parse invalid returns null
        val invalidParsed = OmaIdentity.parse("invalid-id-string")
        assertEquals(null, invalidParsed)
    }

    @Test
    fun testRfc4231HmacSha256TestVectors() {
        val key1 = ByteArray(20) { 0x0b.toByte() }
        val data1 = "Hi There".toByteArray(Charsets.UTF_8)
        val hmac1 = OmaIdentity.hmacSha256(key1, data1)
        val hex1 = hmac1.joinToString("") { "%02x".format(it) }
        assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", hex1)

        val key2 = "Jefe".toByteArray(Charsets.UTF_8)
        val data2 = "what do ya want for nothing?".toByteArray(Charsets.UTF_8)
        val hmac2 = OmaIdentity.hmacSha256(key2, data2)
        val hex2 = hmac2.joinToString("") { "%02x".format(it) }
        assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", hex2)
    }

    @Test
    fun testBlindTopicDerivationHmacSha256() {
        val omaId1 = "4829-1048-5729-1104"
        val omaId2 = "9999-8888-7777-6666"

        val topic1 = OmaIdentity.deriveBlindTopic(omaId1)
        val topic2 = OmaIdentity.deriveBlindTopic(omaId2)

        assertEquals("Topic should be 64-char hex SHA-256 HMAC", 64, topic1.length)
        assertEquals("Topic should be 64-char hex SHA-256 HMAC", 64, topic2.length)
        assertTrue(topic1.all { it in "0123456789abcdef" })

        // Deterministic & unformat-invariant
        assertEquals(topic1, OmaIdentity.deriveBlindTopic(omaId1))
        assertEquals(topic1, OmaIdentity.deriveBlindTopic(OmaIdentity.unformat(omaId1)))
        assertNotEquals(topic1, topic2)

        // HKDF Key Derivation deterministic & 32 bytes
        val key1 = OmaIdentity.deriveRendezvousKey(omaId1)
        val key2 = OmaIdentity.deriveRendezvousKey(omaId2)
        assertEquals(32, key1.size)
        assertEquals(32, key2.size)
        assertTrue(key1.contentEquals(OmaIdentity.deriveRendezvousKey(OmaIdentity.unformat(omaId1))))
        assertFalse(key1.contentEquals(key2))
    }

    @Test
    fun testAes256GcmPayloadRoundtripBinary() {
        val omaId = OmaIdentity.generateRandomOmaId()
        val originalData = "Antigravity Secure E2EE Payload Data 2026".toByteArray(Charsets.UTF_8)

        val encrypted = OmaIdentity.encryptPayload(originalData, omaId)
        assertTrue("Ciphertext should contain 12-byte IV + auth tag", encrypted.size >= originalData.size + 28)

        val decrypted = OmaIdentity.decryptPayload(encrypted, omaId)
        assertTrue("Decrypted data should match original", originalData.contentEquals(decrypted))
    }

    @Test
    fun testAes256GcmStringRoundtripBase64() {
        val omaId = OmaIdentity.generateRandomOmaId()
        val originalText = "OmaSend End-to-End Encrypted Wire Protocol (Zero-Trust)"

        val ciphertextBase64 = OmaIdentity.encryptString(originalText, omaId)
        assertNotNull(ciphertextBase64)
        assertTrue(ciphertextBase64.isNotEmpty())

        val decryptedText = OmaIdentity.decryptString(ciphertextBase64, omaId)
        assertEquals(originalText, decryptedText)
    }

    @Test(expected = Exception::class)
    fun testAes256GcmDecryptionFailsWithWrongKey() {
        val omaId1 = OmaIdentity.generateRandomOmaId()
        val omaId2 = OmaIdentity.generateRandomOmaId()

        val plaintext = "Secret Message"
        val encrypted = OmaIdentity.encryptString(plaintext, omaId1)

        // Attempt decrypt with omaId2 must throw authentication error
        OmaIdentity.decryptString(encrypted, omaId2)
    }

    @Test(expected = Exception::class)
    fun testAes256GcmTamperingDetection() {
        val omaId = OmaIdentity.generateRandomOmaId()
        val originalData = "Tamper Test Data".toByteArray(Charsets.UTF_8)
        val encrypted = OmaIdentity.encryptPayload(originalData, omaId)

        // Tamper with ciphertext byte
        encrypted[encrypted.size - 1] = (encrypted[encrypted.size - 1].toInt() xor 0xFF).toByte()

        OmaIdentity.decryptPayload(encrypted, omaId)
    }

    @Test
    fun testAes256GcmAadAuthentication() {
        val omaId = OmaIdentity.generateRandomOmaId()
        val plaintext = "Authenticated Message Payload".toByteArray(Charsets.UTF_8)
        val aad = "sender_device_id_abc".toByteArray(Charsets.UTF_8)

        val encrypted = OmaIdentity.encryptPayload(plaintext, omaId, aad = aad)
        val decrypted = OmaIdentity.decryptPayload(encrypted, omaId, aad = aad)

        assertTrue(plaintext.contentEquals(decrypted))

        // Wrong AAD should fail decryption
        val wrongAad = "sender_device_id_wrong".toByteArray(Charsets.UTF_8)
        var failed = false
        try {
            OmaIdentity.decryptPayload(encrypted, omaId, aad = wrongAad)
        } catch (_: Exception) {
            failed = true
        }
        assertTrue("Decryption with wrong AAD must fail", failed)
    }
}
