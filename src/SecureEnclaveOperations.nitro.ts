import type { HybridObject } from 'react-native-nitro-modules';

export interface SecureEnclaveOperations
  extends HybridObject<{ ios: 'swift'; android: 'kotlin' }> {
  // Check if App Attestation is available on this device
  isAttestationSupported(): Promise<boolean>;

  // Generate a new key pair and returns the key identifier
  generateKey(): Promise<string>;

  // Certify a key with Apple's servers
  attestKey(keyId: string, challenge: string): Promise<string>;

  // Sign data using the attested key
  generateAssertion(
    keyId: string,
    challenge: string,
    data: string
  ): Promise<string>;
}
