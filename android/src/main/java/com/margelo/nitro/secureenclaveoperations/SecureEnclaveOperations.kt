package com.margelo.nitro.secureenclaveoperations

import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.annotation.Keep
import androidx.annotation.RequiresApi
import com.facebook.proguard.annotations.DoNotStrip
import com.facebook.react.bridge.ReactApplicationContext
import com.margelo.nitro.NitroModules
import com.margelo.nitro.core.Promise
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.UUID
import org.json.JSONObject

@DoNotStrip
@Keep
class SecureEnclaveOperations(private val reactContext: ReactApplicationContext) :
  HybridSecureEnclaveOperationsSpec() {
  private val logTag = "SecureEnclaveOps"

  // Initialize Nitro native code loader
  init {
    Log.d(logTag, "Initializing SecureEnclaveOperations")
    secureenclaveoperationsOnLoad.initializeNative()
  }

  override fun isAttestationSupported(): Promise<Boolean> {
    return Promise.async {
      try {
        Log.d(logTag, "Checking if attestation is supported")

        // Get application context from NitroModules
        val context = NitroModules.applicationContext ?: reactContext

        val isStrongBoxSupported =
          context.packageManager.hasSystemFeature(
            "android.hardware.strongbox_keystore"
          )
        Log.d(logTag, "StrongBox support: $isStrongBoxSupported")

        // We'll just check hardware features for now, without requiring Play Services
        return@async isStrongBoxSupported
      } catch (e: Exception) {
        Log.e(logTag, "Error checking attestation support", e)
        return@async false
      }
    }
  }

  @RequiresApi(Build.VERSION_CODES.P)
  override fun generateKey(): Promise<String> {
    return Promise.async {
      try {
        // Generate a unique key ID
        val keyId = UUID.randomUUID().toString()
        Log.d(logTag, "Generating key with ID: $keyId")
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }


        // Create a key pair generator for EC keys
        val keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
        Log.d(logTag, "Created key pair generator for EC/AndroidKeyStore")

        // Configure the key pair generator with hardware-backed security
        val parameterSpec =
          android.security.keystore.KeyGenParameterSpec.Builder(
            keyId,
            android.security.keystore.KeyProperties.PURPOSE_SIGN or
              android.security.keystore.KeyProperties
                .PURPOSE_VERIFY
          )
            .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256)
            // Make biometric authentication required.
            // Make strongbox hardware backing required
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(true)
            .build()
        Log.d(logTag, "KeyGenParameterSpec built")

        // Generate the key pair with EC algorithm
        keyPairGenerator.initialize(parameterSpec)
        keyPairGenerator.generateKeyPair()
        Log.d(logTag, "Key pair generated")

        val entry = keyStore.getEntry(keyId, null) as? KeyStore.PrivateKeyEntry
        if (entry == null) {
          Log.e(logTag, "Failed to retrieve key entry from KeyStore")
          throw RuntimeException("Failed to generate key")
        }
        Log.d(logTag, "Key successfully verified in KeyStore")

        // Return the key ID to be used for future operations
        return@async keyId
      } catch (e: Exception) {
        Log.e(logTag, "Error generating key", e)
        throw RuntimeException("Error generating key: ${e.message}", e)
      }
    }
  }

  override fun attestKey(keyId: String, challenge: String): Promise<String> {
    return Promise.async {
      try {
        Log.d(logTag, "Attesting key: $keyId with challenge: $challenge")
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        // For now, create a simplified attestation
        // In production, you'd integrate with Google Play Integrity API

        // Get the certificate for this key
        val cert = keyStore.getCertificate(keyId)
        Log.d(logTag, "Retrieved certificate: ${cert != null}")

        val certEncoded =
          if (cert != null) {
            val encoded = Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
            Log.d(logTag, "Certificate encoded, length: ${encoded.length}")
            encoded
          } else {
            Log.w(logTag, "No certificate found for key")
            ""
          }

        // Check if the key is hardware-backed
        val isHwBacked = isHardwareBacked(keyId)
        Log.d(logTag, "Key is hardware backed: $isHwBacked")

        // Get security level
        val secLevel = getSecurityLevel()
        Log.d(logTag, "Security level: $secLevel")

        // Create attestation data with device info and certificate
        val attestationData =
          mapOf(
            "keyId" to keyId,
            "platform" to "android",
            "deviceModel" to Build.MODEL,
            "challenge" to challenge,
            "certificate" to certEncoded,
            "hardwareBackedKey" to isHwBacked,
            "securityLevel" to secLevel
          )
        Log.d(logTag, "Created attestation data with ${attestationData.size} fields")

        // Convert to JSON and encode as Base64
        val jsonAttestation = JSONObject(attestationData).toString()
        val base64Attestation =
          Base64.encodeToString(jsonAttestation.toByteArray(), Base64.NO_WRAP)
        Log.d(logTag, "Attestation encoded, length: ${base64Attestation.length}")

        return@async base64Attestation
      } catch (e: Exception) {
        Log.e(logTag, "Error attesting key", e)
        throw RuntimeException("Error attesting key: ${e.message}", e)
      }
    }
  }

  override fun generateAssertion(
    keyId: String,
    challenge: String,
    data: String
  ): Promise<String> {
    return Promise.async {
      try {
        Log.d(logTag, "Generating assertion for key: $keyId")
        Log.d(logTag, "Challenge length: ${challenge.length}, Data length: ${data.length}")
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        // Create a request object with data and challenge
        val requestData = mapOf("data" to data, "challenge" to challenge)

        // Convert to JSON
        val jsonData = JSONObject(requestData).toString()
        val dataToSign = jsonData.toByteArray()
        Log.d(logTag, "Data to sign prepared, length: ${dataToSign.size} bytes")

        // Get the private key from the key store
        val privateKey = keyStore.getKey(keyId, null) as PrivateKey
        Log.d(logTag, "Retrieved private key from KeyStore")

        // Create a signature using ECDSA
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        Log.d(logTag, "Signature initialized with ECDSA algorithm")

        // Update with the data
        signature.update(dataToSign)
        Log.d(logTag, "Signature updated with data")

        // Sign the data
        val signatureBytes = signature.sign()
        Log.d(
          logTag,
          "Data signed successfully, signature length: ${signatureBytes.size} bytes"
        )

        // Get the certificate for this key
        val cert = keyStore?.getCertificate(keyId)
        val publicKeyEncoded =
          if (cert != null) {
            val encoded =
              Base64.encodeToString(cert.publicKey.encoded, Base64.NO_WRAP)
            Log.d(
              logTag,
              "Public key extracted from certificate, length: ${encoded.length}"
            )
            encoded
          } else {
            Log.w(logTag, "No certificate found for key, cannot extract public key")
            ""
          }

        // Create the assertion object
        val assertionData =
          mapOf(
            "keyId" to keyId,
            "signature" to
              Base64.encodeToString(signatureBytes, Base64.NO_WRAP),
            "publicKey" to publicKeyEncoded,
            "algorithm" to "SHA256withECDSA"
          )
        Log.d(logTag, "Created assertion data object")

        // Convert to JSON and encode as Base64
        val jsonAssertion = JSONObject(assertionData).toString()
        val base64Assertion =
          Base64.encodeToString(jsonAssertion.toByteArray(), Base64.NO_WRAP)
        Log.d(logTag, "Assertion encoded, length: ${base64Assertion.length}")

        return@async base64Assertion
      } catch (e: Exception) {
        Log.e(logTag, "Error generating assertion", e)
        throw RuntimeException("Error generating assertion: ${e.message}", e)
      }
    }
  }

  // Helper method to check if a key is hardware-backed
  private fun isHardwareBacked(keyId: String): Boolean {
    try {
      Log.d(logTag, "Checking if key is hardware-backed: $keyId")
      val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
      val entry = keyStore.getEntry(keyId, null) as? KeyStore.PrivateKeyEntry
      if (entry != null) {
        val privateKey = entry.privateKey
        val isHardwareBacked = privateKey.toString().contains("AndroidKeyStore")
        Log.d(logTag, "Key hardware backing check result: $isHardwareBacked")
        return isHardwareBacked
      }
    } catch (e: Exception) {
      Log.e(logTag, "Error checking if key is hardware-backed", e)
    }
    Log.w(logTag, "Could not determine if key is hardware-backed, assuming false")
    return false
  }

  // Helper method to get the security level
  private fun getSecurityLevel(): String {
    return try {
      Log.d(logTag, "Getting security level")
      // Get application context from NitroModules
      val context = NitroModules.applicationContext ?: reactContext

      if (context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore")) {
        Log.d(logTag, "StrongBox is available")
        "StrongBox"
      } else if (context.packageManager.hasSystemFeature("android.hardware.keystore")) {
        Log.d(logTag, "TEE is available")
        "TEE"
      } else {
        Log.d(logTag, "No hardware security features detected")
        "Software"
      }
    } catch (e: Exception) {
      Log.e(logTag, "Error determining security level", e)
      "Unknown"
    }
  }
}
