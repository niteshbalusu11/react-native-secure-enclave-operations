import { NitroModules } from 'react-native-nitro-modules';
import type { SecureEnclaveOperations } from './SecureEnclaveOperations.nitro';

const SecureEnclaveOperationsHybridObject =
  NitroModules.createHybridObject<SecureEnclaveOperations>(
    'SecureEnclaveOperations'
  );

/**
 * Check if Hardware backed key generation is supported on this device
 *
 * @returns Promise<boolean> - True if the device supports hardware-backed key generation
 */
export function isHardwareBackedKeyGenerationSupported(): Promise<boolean> {
  return SecureEnclaveOperationsHybridObject.isHardwareBackedKeyGenerationSupported();
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
 * Generate a new key pair in the Secure Enclave for App Attestation
 *
 * @returns Promise<string> - Key identifier for the generated key
 */
export function generateKey(): Promise<string> {
  return SecureEnclaveOperationsHybridObject.generateKey();
}

/**
 * Attest a key with Apple's servers
 *
 * @param keyId - Key identifier from generateKey()
 * @param challenge - Challenge from your server (should be unique per attestation)
 * @returns Promise<string> - Base64-encoded attestation object to send to your server
 */
export function attestKey(keyId: string, challenge: string): Promise<string> {
  return SecureEnclaveOperationsHybridObject.attestKey(keyId, challenge);
}

/**
 * Sign data with an attested key
 *
 * @param keyId - Key identifier from generateKey()
 * @param challenge - Challenge from your server (should be unique per request)
 * @param data - Data to sign (usually your request payload)
 * @returns Promise<string> - Base64-encoded assertion object to send to your server
 */
export function generateAssertion(
  keyId: string,
  data: string
): Promise<string> {
  return SecureEnclaveOperationsHybridObject.generateAssertion(keyId, data);
}
