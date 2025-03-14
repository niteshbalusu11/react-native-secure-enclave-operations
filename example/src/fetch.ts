import { Platform } from 'react-native';

const serverUrl =
  Platform.OS === 'android' ? '192.168.4.255:3000' : '192.168.4.255:3000';

export const getChallenge = async () => {
  try {
    const response = await fetch(`http://${serverUrl}/attest/nonce`);
    const data = await response.json();

    console.log('challenge response', data);
    return data.nonce;
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
    const response = await fetch(`http://${serverUrl}/attest/verify`, {
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
  message: string;
};

export const verifyAssertion = async ({
  assertion,
  challenge,
  keyId,
  message,
}: VerifyAssertionArgs) => {
  try {
    // Create authentication header content
    const authContent = {
      keyId,
      assertion,
    };

    // Base64 encode the authentication info
    const authHeader = btoa(JSON.stringify(authContent));

    const clientData = {
      data: message,
      challenge,
    };

    const body = {
      assertion,
      challenge,
      payload: clientData,
      keyId,
    };

    const response = await fetch(`http://${serverUrl}/assertion/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authentication': authHeader,
      },
      body: JSON.stringify(body),
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

export const verifyAndroidIntegrityToken = async ({
  integrityToken,
}: {
  integrityToken: string;
}) => {
  try {
    const response = await fetch(
      `http://${serverUrl}/android/verifyIntegrityToken`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ integrityToken }),
      }
    );

    console.log(
      'verify attestation fetch response',
      response.status,
      response.statusText
    );

    const data = await response.json();

    console.log('android attestation from server', data);
  } catch (err) {
    console.error('error verifying attestation', err);
  }
};

export const verifyAndroidAttestation = async ({
  attestation,
}: {
  attestation: string;
}) => {
  try {
    const response = await fetch(
      `http://${serverUrl}/android/verifyAttestation`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ attestation }),
      }
    );

    console.log(
      'verify attestation fetch response',
      response.status,
      response.statusText
    );

    const data = await response.json();

    console.log('android attestation from server', data);
  } catch (err) {
    console.error('error verifying attestation', err);
  }
};
