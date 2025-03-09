package com.margelo.nitro.secureenclaveoperations

import android.content.Context
import android.util.Base64
import androidx.annotation.Keep
import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.core.Promise
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.UUID
import org.json.JSONObject

@DoNotStrip
@Keep
class SecureEnclaveOperations : HybridSecureEnclaveOperationsSpec() {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    // Initialize Nitro's native code loader
    init {
        secureenclaveoperationsOnLoad.initializeNative()
    }

    override fun isAttestationSupported(): Promise<Boolean> {
        return Promise.async {
            try {
                // Simply return true for now as a placeholder
                // In a real implementation, check for Google Play Services/Integrity API
                return@async true
            } catch (e: Exception) {
                return@async false
            }
        }
    }

    override fun generateKey(): Promise<String> {
        return Promise.async {
            try {
                // Generate a unique key ID
                val keyId = UUID.randomUUID().toString()

                // Create a key pair generator for EC keys
                val keyPairGenerator = KeyPairGenerator.getInstance(
                    "EC",
                    "AndroidKeyStore"
                )

                // Configure the key pair generator
                val parameterSpec = android.security.keystore.KeyGenParameterSpec.Builder(
                    keyId,
                    android.security.keystore.KeyProperties.PURPOSE_SIGN or
                            android.security.keystore.KeyProperties.PURPOSE_VERIFY
                )
                    .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .setInvalidatedByBiometricEnrollment(false)
                    .build()

                // Generate the key pair with EC algorithm
                keyPairGenerator.initialize(parameterSpec)
                keyPairGenerator.generateKeyPair()

                // Return the key ID to be used for future operations
                return@async keyId
            } catch (e: Exception) {
                throw RuntimeException("Error generating key: ${e.message}", e)
            }
        }
    }

    override fun attestKey(keyId: String, challenge: String): Promise<String> {
        return Promise.async {
            try {
                // Create a mock attestation for now
                val attestationData = mapOf(
                    "keyId" to keyId,
                    "platform" to "android",
                    "deviceModel" to android.os.Build.MODEL,
                    "challenge" to challenge,
                    "mockAttestation" to true
                )

                // Convert to JSON and encode as Base64
                val jsonAttestation = JSONObject(attestationData).toString()
                return@async Base64.encodeToString(jsonAttestation.toByteArray(), Base64.NO_WRAP)
            } catch (e: Exception) {
                throw RuntimeException("Error attesting key: ${e.message}", e)
            }
        }
    }

    override fun generateAssertion(keyId: String, challenge: String, data: String): Promise<String> {
        return Promise.async {
            try {
                // Create a request object with data and challenge
                val requestData = mapOf(
                    "data" to data,
                    "challenge" to challenge
                )

                // Convert to JSON
                val jsonData = JSONObject(requestData).toString()

                // Get the private key from the key store
                val privateKey = keyStore.getKey(keyId, null) as PrivateKey

                // Create a signature using ECDSA
                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initSign(privateKey)

                // Update with the data
                signature.update(jsonData.toByteArray())

                // Sign the data
                val signatureBytes = signature.sign()

                // Create the assertion object
                val assertionData = mapOf(
                    "keyId" to keyId,
                    "signature" to Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
                )

                // Convert to JSON and encode as Base64
                val jsonAssertion = JSONObject(assertionData).toString()
                return@async Base64.encodeToString(jsonAssertion.toByteArray(), Base64.NO_WRAP)
            } catch (e: Exception) {
                throw RuntimeException("Error generating assertion: ${e.message}", e)
            }
        }
    }
}
