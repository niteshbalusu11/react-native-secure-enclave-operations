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
import android.content.pm.PackageManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager


@DoNotStrip
@Keep
class SecureEnclaveOperations(private val reactContext: ReactApplicationContext) :
  HybridSecureEnclaveOperationsSpec() {
  private val logTag = "SecureEnclaveOps"
  private var integrityTokenProvider: StandardIntegrityManager.StandardIntegrityTokenProvider? =
    null

  // Initialize Nitro native code loader
  init {
    Log.d(logTag, "Initializing SecureEnclaveOperations")
    secureenclaveoperationsOnLoad.initializeNative()
  }

  override fun isHardwareBackedKeyGenerationSupported(): Promise<Boolean> {
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
            .setInvalidatedByBiometricEnrollment(true)

        val securityLevel = getSecurityLevel()
        val isBiometricSupported = isBiometricEnabled()
        val isBiometricEnrolled = isBiometricEnrolled()

        if (isBiometricSupported && isBiometricEnrolled) {
          parameterSpec.setUserAuthenticationRequired(true)
        } else

          if (securityLevel == PackageManager.FEATURE_STRONGBOX_KEYSTORE && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            parameterSpec.setIsStrongBoxBacked(true)
            Log.d(logTag, "KeyGenParameterSpec backed by hardware strongbox")
          }

        val buildSpec = parameterSpec.build()

        Log.d(logTag, "KeyGenParameterSpec built")

        // Generate the key pair with EC algorithm
        keyPairGenerator.initialize(buildSpec)
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
        val isBioMetricEnabled = isBiometricEnabled()
        val isBioMetricEnrolled = isBiometricEnrolled()
        Log.d(logTag, "isBioMetricEnabled: $isBioMetricEnabled")
        Log.d(logTag, "isBioMetricEnrolled: $isBioMetricEnrolled")

        // Get security level
        val secLevel = getSecurityLevel()
        Log.d(logTag, "Security level: $secLevel")

        // Create attestation data with device info and certificate
        val attestationData = mapOf(
          "keyId" to keyId,
          "platform" to "android",
          "deviceModel" to Build.MODEL,
          "challenge" to challenge,
          "certificate" to certEncoded,
          "biometricEnabled" to isBioMetricEnabled,
          "biometricEnrolled" to isBioMetricEnrolled,
          "securityLevel" to secLevel
        )
        Log.d(logTag, "Created attestation data with ${attestationData.size} fields")

        // Convert to JSON and encode as Base64
        val jsonAttestation = JSONObject(attestationData).toString()
        val base64Attestation =
          Base64.encodeToString(jsonAttestation.toByteArray(), Base64.NO_WRAP)
        Log.d(logTag, "Attestation encoded, length: ${base64Attestation.length}")

        // Hash the attestation to create a shorter request hash (required to be < 500 bytes)
        val messageDigest = java.security.MessageDigest.getInstance("SHA-256")
        val attestationHash = messageDigest.digest(base64Attestation.toByteArray())
        val requestHash = Base64.encodeToString(attestationHash, Base64.NO_WRAP)
        Log.d(logTag, "Created attestation hash for integrity token, length: ${requestHash.length}")

        // Request integrity token using the hashed attestation
        Log.d(logTag, "Requesting integrity token with attestation hash")
        val integrityToken = requestIntegrityToken(requestHash).await()
        Log.d(
          logTag,
          "Integrity token ${if (integrityToken != null) "received" else "not received"}"
        )

        // If we got an integrity token, add it to our attestation and re-encode
        if (integrityToken != null) {
          val attestationWithToken = attestationData + mapOf("integrityToken" to integrityToken)
          val jsonAttestationWithToken = JSONObject(attestationWithToken).toString()
          val base64AttestationWithToken =
            Base64.encodeToString(jsonAttestationWithToken.toByteArray(), Base64.NO_WRAP)
          Log.d(
            logTag,
            "Final attestation with token encoded, length: ${base64AttestationWithToken.length}"
          )
          return@async base64AttestationWithToken
        }

        return@async base64Attestation
      } catch (e: Exception) {
        Log.e(logTag, "Error attesting key", e)
        throw RuntimeException("Error attesting key: ${e.message}", e)
      }
    }
  }

  private fun requestIntegrityToken(requestHash: String): Promise<String?> {
    return Promise.async {
      try {
        if (integrityTokenProvider == null) {
          Log.e(logTag, "Integrity token provider not initialized")
          throw RuntimeException("Integrity token provider not initialized")
        }

        Log.d(logTag, "Requesting integrity token with hash: $requestHash")

        val request = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
          .setRequestHash(requestHash)
          .build()

        var isComplete = false
        var token: String? = null

        integrityTokenProvider?.request(request)
          ?.addOnSuccessListener { response ->
            Log.d(logTag, "Integrity token received successfully")
            token = response.token()
            isComplete = true
          }
          ?.addOnFailureListener { ex ->
            Log.e(logTag, "Failed to get integrity token", ex)
            throw RuntimeException("Failed to get integrity token: ${ex.message}", ex)
          }

        // Wait for completion with timeout
        var attempts = 0
        val maxAttempts = 50 // 5 seconds timeout
        while (!isComplete && attempts < maxAttempts) {
          Thread.sleep(100)
          attempts++
        }

        if (!isComplete) {
          Log.e(logTag, "Timeout while waiting for integrity token")
          throw RuntimeException("Timeout while waiting for integrity token")
        }

        return@async token
      } catch (e: Exception) {
        Log.e(logTag, "Error requesting integrity token", e)
        throw RuntimeException("Error requesting integrity token: ${e.message}", e)
      }
    }
  }

  override fun generateAssertion(
    keyId: String,
    data: String
  ): Promise<String> {
    return Promise.async {
      try {
        Log.d(logTag, "Generating assertion for key: $keyId")
        Log.d(logTag, "Data length: ${data.length}")
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        // Create a request object with data and challenge
        val requestData = mapOf("data" to data)

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

  override fun prepareIntegrityTokenAndroid(cloudProjectNumber: String): Promise<Boolean> {
    return Promise.async {
      try {
        Log.d(logTag, "Preparing integrity token with cloud project number: $cloudProjectNumber")

        // Convert string to long
        val cpn = cloudProjectNumber.toLong()

        val context = NitroModules.applicationContext ?: reactContext

        // Get the integrity manager
        val standardIntegrityManager = IntegrityManagerFactory.createStandard(context)

        // Build the preparation request
        val prepareRequest = StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
          .setCloudProjectNumber(cpn)
          .build()

        // Prepare the token provider
        var isComplete = false
        var result = false

        standardIntegrityManager.prepareIntegrityToken(prepareRequest)
          .addOnSuccessListener { provider ->
            integrityTokenProvider = provider
            Log.d(logTag, "Integrity token provider prepared successfully")
            result = true
            isComplete = true
          }
          .addOnFailureListener { ex ->
            Log.e(logTag, "Failed to prepare integrity token", ex)
            throw RuntimeException("Failed to prepare integrity token: ${ex.message}", ex)
          }

        // Wait for completion
        while (!isComplete) {
          Thread.sleep(100)
        }

        return@async result
      } catch (e: NumberFormatException) {
        Log.e(logTag, "Invalid cloud project number format", e)
        throw RuntimeException("Invalid cloud project number format", e)
      } catch (e: Exception) {
        Log.e(logTag, "Error preparing integrity token", e)
        throw RuntimeException("Error preparing integrity token: ${e.message}", e)
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

  // Check weather the device has biometric enabled
  private fun isBiometricEnabled(): Boolean {
    return try {
      Log.d(logTag, "Checking if biometrics are enabled")
      // Get application context from NitroModules
      val context = NitroModules.applicationContext ?: reactContext

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        val packageManager = context.packageManager
        if (packageManager.hasSystemFeature(PackageManager.FEATURE_FACE) ||
          packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)
        ) {
          Log.d(logTag, "Face or iris recognition hardware is available")
          return true
        }
      }

      val packageManager = context.packageManager
      if (packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
        Log.d(logTag, "Fingerprint hardware is available")
        return true
      }

      Log.d(logTag, "No biometric hardware features detected")
      false
    } catch (e: Exception) {
      Log.e(logTag, "Error checking biometric availability", e)
      false
    }
  }

  // Check if user has set up biometrics on the device
  private fun isBiometricEnrolled(): Boolean {
    return try {
      Log.d(logTag, "Checking if biometrics are enrolled")
      val context = NitroModules.applicationContext ?: reactContext

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        // For Android Q (API 29) and above, use BiometricManager from android.hardware.biometrics
        val biometricManager =
          context.getSystemService(android.hardware.biometrics.BiometricManager::class.java)
        val canAuthenticate =
          biometricManager?.canAuthenticate(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG)

        if (canAuthenticate == android.hardware.biometrics.BiometricManager.BIOMETRIC_SUCCESS) {
          Log.d(logTag, "Biometrics are enrolled and available")
          return true
        }
        Log.d(logTag, "Biometric status code: $canAuthenticate")
      } else {
        // For Android M (API 23) to P (API 28), check keyguard secure
        val keyguardManager =
          context.getSystemService(android.content.Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
        if (keyguardManager.isKeyguardSecure) {
          // If keyguard is secure, biometric or pin/pattern is set up
          Log.d(logTag, "Device is secured with PIN/pattern/biometric")
          return true
        }
      }

      Log.d(logTag, "No enrolled biometrics detected")
      false
    } catch (e: Exception) {
      Log.e(logTag, "Error checking biometric enrollment", e)
      false
    }
  }

  // Helper method to get the security level
  private fun getSecurityLevel(): String {
    return try {
      Log.d(logTag, "Getting security level")
      // Get application context from NitroModules
      val context = NitroModules.applicationContext ?: reactContext

      if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        Log.d(logTag, "StrongBox is available")
        PackageManager.FEATURE_STRONGBOX_KEYSTORE
      } else if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        Log.d(logTag, "TEE is available")
        PackageManager.FEATURE_HARDWARE_KEYSTORE
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
