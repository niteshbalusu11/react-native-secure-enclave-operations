import { NitroModules } from 'react-native-nitro-modules';
import type { SecureEnclaveOperations } from './SecureEnclaveOperations.nitro';

const SecureEnclaveOperationsHybridObject =
  NitroModules.createHybridObject<SecureEnclaveOperations>(
    'SecureEnclaveOperations'
  );

/**
 * iOS ONLY!
 * Check if Hardware backed key generation is supported on this device
 *
 * @returns Promise<boolean> - True if the device supports hardware-backed key generation
 */
export function isHardwareBackedKeyGenerationSupportedIos(): Promise<boolean> {
  return SecureEnclaveOperationsHybridObject.isHardwareBackedKeyGenerationSupportedIos();
}

/**
 * iOS ONLY!
 * Generate a new key pair in the Secure Enclave for App Attestation
 *
 * @returns Promise<string> - Key identifier for the generated key
 */
export function generateKeyIos(): Promise<string> {
  return SecureEnclaveOperationsHybridObject.generateKeyIos();
}

/**
 * iOS ONLY!
 * Attest a key with Apple's servers
 *
 * @param keyId - Key identifier from generateKey()
 * @param challenge - Challenge from your server (should be unique per attestation)
 * @returns Promise<string> - Base64-encoded attestation object to send to your server
 */
export function attestKeyIos(
  keyId: string,
  challenge: string
): Promise<string> {
  return SecureEnclaveOperationsHybridObject.attestKeyIos(keyId, challenge);
}

/**
 * iOS ONLY!
 * Sign data with an attested key
 *
 * @param keyId - Key identifier from generateKey()
 * @param challenge - Challenge from your server (should be unique per request)
 * @param data - Data to sign (usually your request payload)
 * @returns Promise<string> - Base64-encoded assertion object to send to your server
 */
export function generateAssertionIos(
  keyId: string,
  data: string
): Promise<string> {
  return SecureEnclaveOperationsHybridObject.generateAssertionIos(keyId, data);
}

// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
/**
 * ANDROID ONLY!
 * Check if Google Play Services is available on the device
 * @param keyId - Key identifier for the generated key
 * @returns Promise<boolean> - True if Google Play Services is available
 */
export function isPlayServicesAvailableAndroid(): Promise<boolean> {
  return SecureEnclaveOperationsHybridObject.isPlayServicesAvailableAndroid();
}

/**
 * ANDROID ONLY! Prepare an integrity token
 *
 * @returns Promise<boolean> - True if the integrity token was successfully prepared
 */
export function prepareIntegrityTokenAndroid(
  cloudProjectNumber: string
): Promise<boolean> {
  return SecureEnclaveOperationsHybridObject.prepareIntegrityTokenAndroid(
    cloudProjectNumber
  );
}

/**
 * ANDROID ONLY! Request an integrity token
 *
 * @param requestHash - Hash of the request data to be signed
 * @returns Promise<string> - Base64-encoded integrity token to send to your server
 */
export function requestIntegrityTokenAndroid(
  requestHash: string
): Promise<string> {
  return SecureEnclaveOperationsHybridObject.requestIntegrityTokenAndroid(
    requestHash
  );
}

/**
 * ANDROID ONLY! Get attestation with the private key
 *
 * @param challenge - Challenge from your server (should be unique per request)
 * @param keyId - Key identifier from generateKey()
 * @returns Promise<string> - Base64-encoded attestation object to send to your server
 */
export function getAttestationAndroid(
  challenge: string,
  keyId: string
): Promise<string> {
  return SecureEnclaveOperationsHybridObject.getAttestationAndroid(
    challenge,
    keyId
  );
}
