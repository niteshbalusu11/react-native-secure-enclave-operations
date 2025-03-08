# react-native-secure-enclave-operations

Perform cryptographic operations using Apple's Secure Enclave and App Attestation with React Native.
Important node: App attestation service does not work on emulators, you will need to connect a real device.

## Features

- Hardware-backed key generation using Secure Enclave
- App Attestation with Apple's DeviceCheck framework
- Secure asymmetric signing operations
- Verify app integrity for secure server communication

## Requirements

- iOS 14.0 or newer
- Devices with Secure Enclave (iPhone 5s or newer)
- React Native 0.68.0 or newer

## Installation

```sh
npm install react-native-secure-enclave-operations react-native-nitro-modules
```

> `react-native-nitro-modules` is required as this library relies on [Nitro Modules](https://nitro.margelo.com/).


## Platform Support

| Platform | Support                     |
| -------- | --------------------------- |
| iOS      | ✅                          |
| macOS    | ✅                          |
| Android  | ❌ (Work in progress)       |

## API Reference

### App Attestation

```typescript
/**
 * Check if App Attestation is supported on this device
 * @returns Promise<boolean> - True if the device supports App Attestation
 */
function isAttestationSupported(): Promise<boolean>;

/**
 * Generate a new key pair in the Secure Enclave for App Attestation
 * @returns Promise<string> - Key identifier for the generated key
 */
function generateKey(): Promise<string>;

/**
 * Attest a key with Apple's servers
 * @param keyId - Key identifier from generateKey()
 * @param challenge - Challenge from your server (should be unique per attestation)
 * @returns Promise<string> - Base64-encoded attestation object to send to your server
 */
function attestKey(keyId: string, challenge: string): Promise<string>;

/**
 * Sign data with an attested key
 * @param keyId - Key identifier from generateKey()
 * @param challenge - Challenge from your server (should be unique per request)
 * @param data - Data to sign (usually your request payload)
 * @returns Promise<string> - Base64-encoded assertion object to send to your server
 */
function generateAssertion(
  keyId: string, 
  challenge: string, 
  data: string
): Promise<string>;
```

## Usage

### Basic Example

```typescript
import {
  isAttestationSupported,
  generateKey,
  attestKey,
  generateAssertion
} from 'react-native-secure-enclave-operations';

// Check if device supports App Attestation
const isSupported = await isAttestationSupported();
if (!isSupported) {
  console.warn('Device does not support App Attestation');
  return;
}

// Generate a key pair
const keyId = await generateKey();
console.log('Generated key ID:', keyId);

// Attest the key with Apple's servers
const challengeFromServer = 'unique-challenge-from-your-server';
const attestationObject = await attestKey(keyId, challengeFromServer);

// Send attestationObject to your server for verification
const verified = await sendAttestationToServer(attestationObject, challengeFromServer);

// Use the attested key to sign requests
const requestData = JSON.stringify({ userId: 123, action: 'get_data' });
const requestChallenge = 'another-unique-challenge-from-server';
const assertionObject = await generateAssertion(
  keyId, 
  requestChallenge, 
  requestData
);

// Include the assertion in your authenticated request
const response = await fetch('https://api.yourserver.com/secure-endpoint', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-App-Attest-Assertion': assertionObject,
    'X-App-Attest-Challenge': requestChallenge
  },
  body: requestData
});
```

### React Native Example:

See the [example app](https://github.com/niteshbalusu11/react-native-secure-enclave-operations/tree/main/example).

## Security Considerations

- Store the key ID securely, preferably in the device's Keychain
- Rotate keys periodically for enhanced security
- Use unique challenges for each attestation and assertion
- Implement proper error handling for failed attestations

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)