# Mobile App Security Server

A Node.js server implementing security verification for both iOS and Android apps. This server provides endpoints for device attestation and integrity verification.

## Features

- **iOS App Attestation**: Verify app authenticity using Apple's App Attestation service
- **Android Device Verification**: Support for both Google Play Integrity API and Hardware Attestation
- **Challenge-Response Authentication**: Secure nonce-based authentication flow

## Installation

To install dependencies:

```bash
bun install
```

## Configuration

Create a `.env` file with the following variables:

```
# iOS Configuration
BUNDLE_IDENTIFIER=your.ios.app.bundleid
TEAM_IDENTIFIER=your_apple_team_id

# Android Configuration
ANDROID_BUNDLE_IDENTIFIER=your.android.app.packagename

# Server Configuration
PORT=3000
```

### Android Keys
- Add a `keys.json` in the file at the root of the `server` directory with your Google Cloud service account credentials for the Google Play Integrity API.
- Check the `keys_sample.json` file for a sample configuration.

## Running the Server

### Development Mode

```bash
bun run dev
```

This starts the server with hot reloading enabled.

### Production Mode

```bash
bun run index.ts
```

## API Endpoints

### iOS Attestation

- `GET /attest/nonce`: Get a challenge nonce
- `POST /attest/verify`: Verify iOS app attestation
- `POST /assertion/verify`: Verify subsequent assertions

### Android Verification

- `GET /attestation/nonce`: Get a challenge nonce
- `POST /android/verifyIntegrityToken`: Verify a Google Play Integrity token
- `POST /android/verifyAttestation`: Verify Android hardware key attestation

## Security Considerations

This is a reference implementation with simplified storage. In production:

- Store attestations in a secure database
- Implement proper error handling and rate limiting
- Consider adding TLS and additional security headers
- Configure proper logging levels

## Project Structure

- `android/`: Android-specific verification code
- `verifyAttestation.ts`: iOS attestation verification
- `verifyAssertion.ts`: iOS assertion verification
- `index.ts`: Main server implementation

## Technologies

- [Bun](https://bun.sh): JavaScript runtime
- [Express](https://expressjs.com): Web server framework
- [googleapis](https://github.com/googleapis/google-api-nodejs-client): Google API client library
- [cbor](https://github.com/hildjj/node-cbor): CBOR encoding/decoding
- [pkijs](https://github.com/PeculiarVentures/PKI.js): Public Key Infrastructure library
