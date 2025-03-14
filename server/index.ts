import express from 'express';
import { v4 as uuid } from 'uuid';
import { Buffer } from 'node:buffer';

import verifyAttestation from './verifyAttestation.ts';
import bodyParser from 'body-parser';

import androidRouter from './android/androidRouter.ts';
import verifyAssertion from './verifyAssertion.ts';

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

const port = Bun.env.PORT || 3000;
export let nonce = uuid();

// Please note that this is a simple example and the attestation should be stored in a secure way.
// Every time the server restarts, the attestation is lost. Every time the app verify the attestation
// this value be overwritten. This is just a simple example.
let attestation: any = null;

// The bundle identifier and team identifier are used to verify the attestation and assertion.
const BUNDLE_IDENTIFIER = Bun.env.BUNDLE_IDENTIFIER || '';
const TEAM_IDENTIFIER = Bun.env.TEAM_IDENTIFIER || '';
export const GOOGLE_APPLICATION_CREDENTIALS =
  await Bun.file('keys.json').text();

export const ANDROID_BUNDLE_IDENTIFIER =
  Bun.env.ANDROID_BUNDLE_IDENTIFIER || '';

/**
 * Router for the android specific endpoints.
 */
app.use('/android', androidRouter);

/**
 * This endpoint is used to get the nonce for the attestation process.
 * The nonce is a random string that is used to prevent replay attacks.
 * The nonce is generated on the server and sent to the client.
 * The client then sends the nonce back to the server as part of the attestation process.
 */
app.get('/attest/nonce', (_, res) => {
  nonce = uuid();
  console.debug(`challange was requested, returning ${nonce}`);
  res.send(JSON.stringify({ nonce }));
});

/**
 * This endpoint is used to verify the attestation.
 * The client sends the attestation and the challenge back to the server.
 * The server then verifies the attestation and stores the public key for later use.
 * The server also stores the keyId and the signCount.
 */
app.post(`/attest/verify`, (req, res) => {
  try {
    console.debug(`verify was requested: ${JSON.stringify(req.body, null, 2)}`);
    if (nonce !== req.body.challenge) {
      throw new Error('Invalid challenge');
    }

    const result = verifyAttestation({
      attestation: Buffer.from(req.body.attestation, 'base64'),
      challenge: req.body.challenge,
      keyId: req.body.keyId,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
      allowDevelopmentEnvironment: true,
    });

    // store the attestation for later use
    attestation = {
      keyId: req.body.hardwareKeyTag,
      publicKey: result.publicKey,
      signCount: 0, // is this be set incrementally?
    };

    res.json({ result });
  } catch (error) {
    console.error(error);
    res.status(401).send({ error: 'Unauthorized' });
  }
});
/**
 * This endpoint is used to verify the assertion.
 * The client sends the assertion and the challenge back to the server.
 * The server then verifies the assertion using the stored public key.
 * The server also verifies the signCount and stores the new signCount.
 */
app.post(`/assertion/verify`, (req, res) => {
  try {
    const { keyId } = req.body;

    if (keyId === undefined) {
      throw new Error('Invalid authentication');
    }

    if (nonce !== req.body.challenge) {
      throw new Error('Invalid challenge');
    }

    if (!attestation) {
      throw new Error('No attestation found');
    }

    const result = verifyAssertion({
      assertion: Buffer.from(req.body.assertion, 'base64'),
      payload: JSON.stringify(req.body.payload),
      publicKey: attestation.publicKey,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
      signCount: attestation.signCount,
    });

    console.debug(`Received message: ${JSON.stringify(req.body)}`);

    res.send({ result });
  } catch (error) {
    console.error(error);
    res.status(401).send({ error: 'Unauthorized' });
  }
});

app.listen(port, () => {
  console.log(`[server] server is running at http://localhost:${port}`);
  // Check if the environment variables are set, if not, a warning is displayed.
  if (!GOOGLE_APPLICATION_CREDENTIALS)
    console.warn('[server] GOOGLE_APPLICATION_CREDENTIALS is not set in .env');
  else {
    try {
      JSON.parse(GOOGLE_APPLICATION_CREDENTIALS);
    } catch (error) {
      console.warn(
        '[server] GOOGLE_APPLICATION_CREDENTIALS is not a valid JSON in .env'
      );
    }
  }
  if (!ANDROID_BUNDLE_IDENTIFIER)
    console.warn('[server] ANDROID_BUNDLE_IDENTIFIER is not set in .env');
  if (!BUNDLE_IDENTIFIER)
    console.warn('[server] BUNDLE_IDENTIFIER is not set in .env');
  if (!TEAM_IDENTIFIER)
    console.warn('[server] TEAM_IDENTIFIER is not set in .env');
});
