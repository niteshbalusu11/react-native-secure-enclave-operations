package com.margelo.nitro.secureenclaveoperations

import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.annotation.Keep
import com.facebook.proguard.annotations.DoNotStrip
import com.facebook.react.bridge.ReactApplicationContext
import com.margelo.nitro.NitroModules
import com.margelo.nitro.core.Promise
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.gms.common.ConnectionResult
import java.security.KeyFactory


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

  override fun isPlayServicesAvailableAndroid(): Promise<Boolean> {
    return Promise.async {
      val context = NitroModules.applicationContext ?: reactContext

      val status =
        GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context)
      val isAvailable = status in listOf(
        ConnectionResult.SUCCESS,
        ConnectionResult.SERVICE_UPDATING,
        ConnectionResult.SERVICE_VERSION_UPDATE_REQUIRED
      )
      return@async isAvailable
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

  override fun requestIntegrityTokenAndroid(requestHash: String): Promise<String> {
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
        var token: String = ""

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

  override fun getAttestationAndroid(challenge: String, keyId: String): Promise<String> {
    return Promise.async {
      try {
        val context = NitroModules.applicationContext ?: reactContext

        // Check if key already exists and delete it if needed
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (keyStore.containsAlias(keyId)) {
          keyStore.deleteEntry(keyId)
        }

        // Check for StrongBox support
        val hasStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
          context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

        // Generate attestation key with challenge
        val keyPairGenerator = KeyPairGenerator.getInstance(
          KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        val builder = KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_SIGN)
          .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
          .setDigests(KeyProperties.DIGEST_SHA256)
          .setAttestationChallenge(challenge.toByteArray())

        if (hasStrongBox) {
          builder.setIsStrongBoxBacked(true)
        }

        keyPairGenerator.initialize(builder.build())
        val keyPair = keyPairGenerator.generateKeyPair()

        // Verify hardware backing
        if (!isKeyHardwareBacked(keyPair.private)) {
          throw RuntimeException("Key is not hardware backed")
        }

        // Get certificate chain
        val chain = keyStore.getCertificateChain(keyId)
        var attestations = arrayOf<String>()
        chain.forEach { certificate ->
          // Encode without line breaks to prevent parsing issues
          val cert = Base64.encodeToString(certificate.encoded, Base64.NO_WRAP)
          attestations += cert
        }

        // Join with a delimiter that won't appear in Base64 encoding
        val concatenatedAttestations = attestations.joinToString("|")
        return@async Base64.encodeToString(concatenatedAttestations.toByteArray(), Base64.NO_WRAP)
      } catch (e: Exception) {
        Log.e(logTag, "Error attesting key", e)
        throw RuntimeException("Error attesting key: ${e.message}", e)
      }
    }
  }

  private fun isKeyHardwareBacked(key: PrivateKey): Boolean {
    try {
      val factory = KeyFactory.getInstance(
        key.algorithm, "AndroidKeyStore"
      )
      val keyInfo = factory.getKeySpec(key, KeyInfo::class.java)
      return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
          keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
          keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE
      } else {
        @Suppress("DEPRECATION")
        keyInfo.isInsideSecureHardware
      }
    } catch (e: Exception) {
      return false
    }
  }

  private fun generateKeyAndroid(keyId: String): Promise<String> {
    return Promise.async {
      try {
        // Generate a unique key ID
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

  private fun isHardwareBackedKeyGenerationSupported(): Promise<Boolean> {
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


  override fun isHardwareBackedKeyGenerationSupportedIos(): Promise<Boolean> {
    throw RuntimeException("This method is for iOS only!")
  }

  override fun generateKeyIos(): Promise<String> {
    throw RuntimeException("This method is for iOS only!")
  }

  override fun attestKeyIos(keyId: String, challenge: String): Promise<String> {
    throw RuntimeException("This method is for iOS only!")
  }

  override fun generateAssertionIos(keyId: String, data: String): Promise<String> {
    throw RuntimeException("This method is for iOS only!")
  }
}
