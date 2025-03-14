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
            result = true
            isComplete = true
          }
          .addOnFailureListener { ex ->
            throw RuntimeException("Failed to prepare integrity token: ${ex.message}", ex)
          }

        // Wait for completion
        while (!isComplete) {
          Thread.sleep(100)
        }

        return@async result
      } catch (e: NumberFormatException) {
        throw RuntimeException("Invalid cloud project number format", e)
      } catch (e: Exception) {
        throw RuntimeException("Error preparing integrity token: ${e.message}", e)
      }
    }
  }

  override fun requestIntegrityTokenAndroid(requestHash: String): Promise<String> {
    return Promise.async {
      try {
        if (integrityTokenProvider == null) {
          throw RuntimeException("Integrity token provider not initialized")
        }

        val request = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
          .setRequestHash(requestHash)
          .build()

        var isComplete = false
        var token: String = ""

        integrityTokenProvider?.request(request)
          ?.addOnSuccessListener { response ->
            token = response.token()
            isComplete = true
          }
          ?.addOnFailureListener { ex ->
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
          throw RuntimeException("Timeout while waiting for integrity token")
        }

        return@async token
      } catch (e: Exception) {
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
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }


        // Create a key pair generator for EC keys
        val keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")

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
          }

        val buildSpec = parameterSpec.build()

        // Generate the key pair with EC algorithm
        keyPairGenerator.initialize(buildSpec)
        keyPairGenerator.generateKeyPair()

        val entry = keyStore.getEntry(keyId, null) as? KeyStore.PrivateKeyEntry
        if (entry == null) {
          throw RuntimeException("Failed to generate key")
        }

        // Return the key ID to be used for future operations
        return@async keyId
      } catch (e: Exception) {
        throw RuntimeException("Error generating key: ${e.message}", e)
      }
    }
  }

  private fun isHardwareBackedKeyGenerationSupported(): Promise<Boolean> {
    return Promise.async {
      try {
        // Get application context from NitroModules
        val context = NitroModules.applicationContext ?: reactContext

        val isStrongBoxSupported =
          context.packageManager.hasSystemFeature(
            "android.hardware.strongbox_keystore"
          )

        // We'll just check hardware features for now, without requiring Play Services
        return@async isStrongBoxSupported
      } catch (e: Exception) {
        return@async false
      }
    }
  }

  // Helper method to check if a key is hardware-backed
  private fun isHardwareBacked(keyId: String): Boolean {
    try {
      val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
      val entry = keyStore.getEntry(keyId, null) as? KeyStore.PrivateKeyEntry
      if (entry != null) {
        val privateKey = entry.privateKey
        val isHardwareBacked = privateKey.toString().contains("AndroidKeyStore")
        return isHardwareBacked
      }
    } catch (e: Exception) {
    }
    Log.w(logTag, "Could not determine if key is hardware-backed, assuming false")
    return false
  }

  // Check weather the device has biometric enabled
  private fun isBiometricEnabled(): Boolean {
    return try {
      // Get application context from NitroModules
      val context = NitroModules.applicationContext ?: reactContext

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        val packageManager = context.packageManager
        if (packageManager.hasSystemFeature(PackageManager.FEATURE_FACE) ||
          packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)
        ) {
          return true
        }
      }

      val packageManager = context.packageManager
      if (packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
        return true
      }

      false
    } catch (e: Exception) {
      false
    }
  }

  // Check if user has set up biometrics on the device
  private fun isBiometricEnrolled(): Boolean {
    return try {
      val context = NitroModules.applicationContext ?: reactContext

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        // For Android Q (API 29) and above, use BiometricManager from android.hardware.biometrics
        val biometricManager =
          context.getSystemService(android.hardware.biometrics.BiometricManager::class.java)
        val canAuthenticate =
          biometricManager?.canAuthenticate(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG)

        if (canAuthenticate == android.hardware.biometrics.BiometricManager.BIOMETRIC_SUCCESS) {
          return true
        }
      } else {
        // For Android M (API 23) to P (API 28), check keyguard secure
        val keyguardManager =
          context.getSystemService(android.content.Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
        if (keyguardManager.isKeyguardSecure) {
          // If keyguard is secure, biometric or pin/pattern is set up
          return true
        }
      }

      false
    } catch (e: Exception) {
      false
    }
  }

  // Helper method to get the security level
  private fun getSecurityLevel(): String {
    return try {
      // Get application context from NitroModules
      val context = NitroModules.applicationContext ?: reactContext

      if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        PackageManager.FEATURE_STRONGBOX_KEYSTORE
      } else if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        PackageManager.FEATURE_HARDWARE_KEYSTORE
      } else {
        "Software"
      }
    } catch (e: Exception) {
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
