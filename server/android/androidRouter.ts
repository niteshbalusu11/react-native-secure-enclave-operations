import express, { Router } from 'express';
import { verifyAttestation, verifyIntegrityToken } from './androidIntegrity.ts';
import {
  ANDROID_BUNDLE_IDENTIFIER,
  GOOGLE_APPLICATION_CREDENTIALS,
} from '../index.ts';
import { Buffer } from 'node:buffer';

const router: Router = express.Router();

/**
 * Verifies a Google Play Integrity Token.
 * The check is done for a standard request and the token is decrypted and verified on Google Cloud, not locally.
 * The GOOGLE_APPLICATION_CREDENTIALS and ANDROID_BUNDLE_IDENTIFIER environment variables must be set.
 * @param integrityToken - The integrity token to verify.
 * @returns The result of the integrity token verification.
 */
router.post('/verifyIntegrityToken', async (req, res) => {
  console.debug(
    `Play integrity verdict was requested: ${JSON.stringify(req.body, null, 2)}`
  );
  if (!GOOGLE_APPLICATION_CREDENTIALS || !ANDROID_BUNDLE_IDENTIFIER) {
    res.status(500).send({
      error:
        'GOOGLE_APPLICATION_CREDENTIALS and ANDROID_BUNDLE_INDENTIFIER must be set in the .env file',
    });
    return;
  }
  try {
    const googleCredentials = JSON.parse(GOOGLE_APPLICATION_CREDENTIALS);
    const { integrityToken } = req.body;

    if (integrityToken === undefined) {
      res.status(400).send({ error: 'Invalid integrity token' });
      return;
    }
    const { data } = await verifyIntegrityToken(
      googleCredentials.client_email,
      googleCredentials.private_key,
      ANDROID_BUNDLE_IDENTIFIER,
      integrityToken
    );

    console.log(data);

    res.send(data);
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .send({ error: 'An error occurred while verifying the integrity token' });
  }
});

/**
 * Verifies a key attestation which is a signed statement from a secure hardware module that attests to the security properties of the module.
 * On Android it is represented as a chain of X.509 certificates.
 * See {@link verifyAttestation} for more details.
 * @param attestation - The key attestation to verify
 * @param challenge - The challenge that was used to generate the attestation
 * @returns The result of the chain verification.
 */
router.post('/verifyAttestation', async (req, res) => {
  console.debug(
    `Key attestation verdict was requested: ${JSON.stringify(req.body, null, 2)}`
  );
  try {
    // Get the nonce from the server context
    const { attestation, challenge } = req.body;

    // Import the nonce from the main server file
    const { nonce } = await import('../index.ts');

    // Validate the challenge matches the server's nonce
    if (!challenge || challenge !== nonce) {
      throw new Error('Invalid or missing challenge');
    }

    await verifyAttestation(attestation, challenge);
    res.status(200).send({ result: 'Attestation verified' });
  } catch (error) {
    console.error(error);
    res.status(500).send({
      error: `An error occurred while verifying the key attestation token: ${error}`,
    });
  }
});

export default router;
