# react-native-secure-enclave-operations

Perform cryptographic operations using Apple's Secure Enclave and App Attestation with React Native.

<b>Important Note: App attestation service in iOS and Hardware-backed key generation in Android does not work on emulators, you will need to connect a real device.</b>

## Features

- Hardware-backed key generation using Secure Enclave
- App Attestation with Apple's DeviceCheck framework
- Play Store Attestation with Google's Play Integrity API
- Secure asymmetric signing operations
- Verify app integrity for secure server communication

## Requirements

- iOS 14.0 or newer
- Devices with Secure Enclave (iPhone 5s or newer)
- React Native 0.75.0 or newer

## Installation

```sh
npm install react-native-secure-enclave-operations react-native-nitro-modules
```

> `react-native-nitro-modules` is required as this library relies on [Nitro Modules](https://nitro.margelo.com/).

## Platform Support

| Platform | Support               |
| -------- | --------------------- |
| iOS      | ✅                    |
| MacOS    | ✅                    |
| Android  | ✅                    |

### Directory Structure
```
|-android/ (Kotlin implementation for Android)
|-ios/ (Swift implementation for iOS)
|-src/ (TypeScript definitions methods for NitroModules)
|-server/ (Sample Node.js implementation for server)
|-example/ (Sample React Native client side implementation)
  |-src/
```

## API Reference

### App Attestation (iOS)

```typescript
/**
 * Check if App Attestation is supported on this device
 * @returns Promise<boolean> - True if the device supports App Attestation
 */
function isAttestationSupportedIos(): Promise<boolean>;

/**
 * Generate a new key pair in the Secure Enclave for App Attestation
 * @returns Promise<string> - Key identifier for the generated key
 */
function generateKeyIos(): Promise<string>;

/**
 * Attest a key with Apple's servers
 * @param keyId - Key identifier from generateKey()
 * @param challenge - Challenge from your server (should be unique per attestation)
 * @returns Promise<string> - Base64-encoded attestation object to send to your server
 */
function attestKeyIos(keyId: string, challenge: string): Promise<string>;

/**
 * Sign data with an attested key
 * @param keyId - Key identifier from generateKey()
 * @param data - Data to sign (usually your request payload)
 * @returns Promise<string> - Base64-encoded assertion object to send to your server
 */
function generateAssertionIos(keyId: string, data: string): Promise<string>;
```


### Play Integrity (Android)

```typescript
/**
 * Check if Google Play Services is available on the device
 * @returns Promise<boolean> - True if Google Play Services is available
 */
function isPlayServicesAvailableAndroid(): Promise<boolean>;

/**
 * Prepare an integrity token for Google Play Integrity API
 * @param cloudProjectNumber - Cloud project number from Google Cloud Console
 * @returns Promise<boolean> - True if the integrity token was successfully prepared
 */
function prepareIntegrityTokenAndroid(cloudProjectNumber: string): Promise<boolean>;

/**
 * @param requestHash - Hash of the request data to be signed
 * @returns Promise<string> - Base64-encoded integrity token to send to your server
 */
export function requestIntegrityTokenAndroid(requestHash: string): Promise<string>;

/**
 * @param challenge - Challenge from your server (should be unique per request)
 * @param keyId - Key identifier from generateKey()
 * @returns Promise<string> - Base64-encoded attestation object to send to your server
 */
export function getAttestationAndroid(challenge: string, keyId: string): Promise<string>
```


## Usage

### Basic Example iOS

```typescript
import {
  isHardwareBackedKeyGenerationSupportedIos,
  generateKeyIos,
  attestKeyIos,
  generateAssertionIos,
} from 'react-native-secure-enclave-operations';

// NOTE: The server functions are placeholders.
// Check the server/ directory for a sample implementation.

// Check if device supports hardware-backed key generation
const isSupported = await isHardwareBackedKeyGenerationSupportedIos();
if (!isSupported) {
  console.warn('Device does not support hardware-backed key generation');
  return;
}

// Generate a key pair
const keyId = await generateKeyIos();
console.log('Generated key ID:', keyId);

// Fetch a challenge from your server
const challenge = await fetchChallengeFromServer();

// Attest the key with Apple's servers
const attestationObject = await attestKeyIos(keyId, challenge);

// Send attestationObject to your server for verification
await verifyAttestationWithServer(attestationObject, challenge, keyId);

// Get another unique challenge from your server
const anotherChallenge = await fetchChallengeFromServer();

// Use the key to sign data
const message = 'data to sign';
const data = {
  data: message,
  challenge: anotherChallenge,
};
const assertion = await generateAssertionIos(keyId, JSON.stringify(data));

// Verify the assertion with your server
await verifyAssertionWithServer({
  assertion,
  challenge,
  keyId,
  message,
});
```

### Basic Example Android
```typescript
import {
  isPlayServicesAvailableAndroid,
  prepareIntegrityTokenAndroid,
  requestIntegrityTokenAndroid,
  getAttestationAndroid,
} from 'react-native-secure-enclave-operations';
import uuid from 'react-native-uuid';

// NOTE: The server functions are placeholders.
// Check the server/ directory for a sample implementation.

// Check if Play Services is available
const isAvailable = await isPlayServicesAvailableAndroid();
if (!isAvailable) {
  console.warn('Google Play Services is not available');
  return;
}

// Prepare integrity token (should be called when app starts)
const cloudProjectNumber = 'your-cloud-project-number';
await prepareIntegrityTokenAndroid(cloudProjectNumber);

// Fetch a challenge from your server
const challenge = await fetchChallengeFromServer();

// Request an integrity token
const integrityToken = await requestIntegrityTokenAndroid(challenge);

// Send the integrity token to your server for verification
await verifyIntegrityTokenWithServer(integrityToken);

// Generate a key attestation (hardware-backed)
const keyId = uuid.v4();
const attestation = await getAttestationAndroid(challenge, keyId);

// Send the attestation to your server for verification
await verifyAttestationWithServer(attestation);
```

### React Native Example:

See the [example app](https://github.com/niteshbalusu11/react-native-secure-enclave-operations/tree/main/example).

### Server side implementation
See this [server/](https://github.com/niteshbalusu11/react-native-secure-enclave-operations/tree/master/server/) directory for details on how to implement the server-side verification.

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
