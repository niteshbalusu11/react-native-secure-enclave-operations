import type { HybridObject } from 'react-native-nitro-modules';

export interface SecureEnclaveOperations
  extends HybridObject<{ ios: 'swift'; android: 'kotlin' }> {
  // Check if hardware-backed key generation is available on this device
  isHardwareBackedKeyGenerationSupported(): Promise<boolean>;

  // ANDROID ONLY! Prepare an integrity token
  // This needs to be called when the app starts
  // Well before you try to attest a key
  prepareIntegrityTokenAndroid(cloudProjectNumber: string): Promise<boolean>;

  // Generate a new key pair and returns the key identifier
  generateKey(): Promise<string>;

  // Certify a key with Apple's servers
  attestKey(keyId: string, challenge: string): Promise<string>;

  // Sign data using the attested key
  generateAssertion(keyId: string, data: string): Promise<string>;
}
