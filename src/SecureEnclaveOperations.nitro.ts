import type { HybridObject } from 'react-native-nitro-modules';

export interface SecureEnclaveOperations
  extends HybridObject<{ ios: 'swift'; android: 'kotlin' }> {
  // iOS ONLY!
  // Check if hardware-backed key generation is available on this device
  isHardwareBackedKeyGenerationSupportedIos(): Promise<boolean>;

  // iOS ONLY!
  // Generate a new key pair and returns the key identifier
  generateKeyIos(): Promise<string>;

  // iOS ONLY!
  // Certify a key with Apple's servers
  attestKeyIos(keyId: string, challenge: string): Promise<string>;

  // iOS ONLY!
  // Sign data using the attested key
  generateAssertionIos(keyId: string, data: string): Promise<string>;

  // ANDROID ONLY!
  // Generate a new key pair and returns the key identifier
  isPlayServicesAvailableAndroid(): Promise<boolean>;

  // ANDROID ONLY! Prepare an integrity token
  // This needs to be called when the app starts
  // Well before you try to request an integrity token
  prepareIntegrityTokenAndroid(cloudProjectNumber: string): Promise<boolean>;

  // ANDROID ONLY! Request an integrity token
  // This needs to be called on demand, when you need to request
  // An integrity token from Google's servers
  requestIntegrityTokenAndroid(requestHash: string): Promise<string>;

  // ANDROID ONLY! Get attestation with the private key
  // Use this when you need to verify certificate chain
  getAttestationAndroid(challenge: string, keyId: string): Promise<string>;
}
