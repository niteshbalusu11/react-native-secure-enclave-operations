import { Platform } from 'react-native';

const serverUrl =
  Platform.OS === 'android' ? '10.0.2.2:3000' : '192.168.6.199:3000';

export const getChallenge = async () => {
  try {
    const response = await fetch(`http://${serverUrl}/v1/attest/challenge`);
    const data = await response.json();

    console.log('challenge response', data);
    return data.challenge;
  } catch (err) {
    console.error('error getting challenge', err);
  }
};

type VerifyAttestationArgs = {
  attestation: string;
  challenge: string;
  keyId: string;
};
export const verifyAttestation = async ({
  attestation,
  challenge,
  keyId,
}: VerifyAttestationArgs) => {
  try {
    const response = await fetch(`http://${serverUrl}/v1/attest/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ attestation, challenge, keyId }),
    });

    console.log(
      'verify attestation fetch response',
      response.status,
      response.statusText
    );
  } catch (err) {
    console.error('error verifying attestation', err);
  }
};

type VerifyAssertionArgs = {
  assertion: string;
  challenge: string;
  keyId: string;
  message?: string; // Optional message content
};

export const verifyAssertion = async ({
  assertion,
  challenge,
  keyId,
  message = 'Hello server',
}: VerifyAssertionArgs) => {
  try {
    // Create authentication header content
    const authContent = {
      keyId,
      assertion,
    };

    // Base64 encode the authentication info using btoa for React Native
    const authHeader = btoa(JSON.stringify(authContent));

    // Create the message payload including the challenge
    const messagePayload = {
      challenge,
      message,
      timestamp: new Date().toISOString(),
    };

    const response = await fetch(`http://${serverUrl}/v1/send-message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authentication': authHeader,
      },
      body: JSON.stringify(messagePayload),
    });

    console.log(
      'message with assertion response',
      response.status,
      response.statusText
    );

    return response.status === 204;
  } catch (err) {
    console.error('error sending authenticated message', err);
    return false;
  }
};
