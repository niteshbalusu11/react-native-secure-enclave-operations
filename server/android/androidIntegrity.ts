import { google } from 'googleapis';
import { X509Certificate } from 'node:crypto';
import asn1js from 'asn1js';
import pkijs from 'pkijs';
import fs from 'node:fs';
import crypto from 'node:crypto';

/**
 * Simplified type definition for the Certificate Revocation List (CRL) object.
 */
type CRL = {
  entries: Record<
    string,
    { status: string; expires: string; reason: string; comment: string }
  >;
};

// Certificate Revocation status List
// https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status
const CRL_URL = 'https://android.googleapis.com/attestation/status';
// Key attestation extension data schema OID
// https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema
const KEY_OID = '1.3.6.1.4.1.11129.2.1.17';

export const playintegrity = google.playintegrity('v1');

/**
 * Calls the Google Play Integrity API to verify and decrypt an integrity token.
 * @param credentialClientEmail - The service account email.
 * @param credentialPrivateKey - The private key of the service account.
 * @param packageName - The package name of the app which generated the integrity token.
 * @param integrityToken - The integrity token to verify.
 * @returns an object containing the result of the integrity token verification. This token shouldn't be returned to the client.
 * A simple yes/no answer should be returned to the client instead, based on the result of the verification.
 */
export const verifyIntegrityToken = async (
  credentialClientEmail: string,
  credentialPrivateKey: string,
  packageName: string,
  integrityToken: string
) => {
  let jwtClient = new google.auth.JWT(
    credentialClientEmail,
    undefined,
    credentialPrivateKey,
    ['https://www.googleapis.com/auth/playintegrity']
  );
  google.options({ auth: jwtClient });
  return await playintegrity.v1.decodeIntegrityToken({
    packageName,
    requestBody: {
      integrityToken,
    },
  });
};

/**
 * Verifies a key attestation which is a signed statement from a secure hardware module that attests to the security properties of the module.
 * Verifies the challenge from the server exists in the certificate returned.
 * On Android it is represented as a chain of X.509 certificates.
 * The native implementation contacates the chain of certificates into a single base64 encoded string divided by commas.
 * {@link https://developer.android.com/training/articles/security-key-attestation}
 * 1st and 2nd steps are not implemented here as they are done on the client side.
 * Functions used to verify the attestation have their relative steps commented in the TSdoc.
 * Even though some steps might be joined in a single function, they are separated in the comments for clarity at the cost of some repetition.
 * The 5th step is not implemented as it is only implemented in newer chains.
 * The 7th step which compares the attestation extension data with a fixed set of expected values is not implemented in this example as it heavily depends on the specific use case.
 * @param x509Array - The chain of X.509 certificates in base64 format divided by commas.
 * @param expectedChallenge - The expected challenge that was used to generate the attestation.
 * @throws {Error} - If the attestation is invalid.
 */
export const verifyAttestation = async (
  x509Array: string,
  expectedChallenge: string
) => {
  // We split the chain of certificates and convert them to PEM format to be parsed by the X509Certificate class
  const decodedString = Buffer.from(x509Array, 'base64').toString('utf-8');

  // Use the new delimiter
  const certificates = decodedString.split('|');
  const x509Chain = certificates.map((cert) => {
    // Format as proper PEM with newlines every 64 characters
    const formatted = cert.replace(/(.{64})/g, '$1\n');
    return new X509Certificate(base64ToPem(formatted));
  });
  validateIssuance(x509Chain);
  await validateRevokation(x509Chain);
  validateKeyAttestationExtension(x509Chain);

  // The attestation certificate is the first one in the chain
  const attestationCert = x509Chain[0];

  // For Android Key Attestation, we need to check the attestation extension in the leaf certificate
  const rawCertData = attestationCert.raw;

  // Parse the certificate ASN.1 structure
  const asn1 = asn1js.fromBER(rawCertData);
  const certificate = new pkijs.Certificate({ schema: asn1.result });

  console.log('Analyzing certificate extensions:');

  // Look for key attestation data in certificate extensions
  if (!certificate.extensions || certificate.extensions.length === 0) {
    throw new Error('Certificate contains no extensions');
  }

  // Log all extensions to help debugging
  certificate.extensions.forEach((ext) => {
    console.log(`Extension: ${ext.extnID}`);
  });

  // Android KeyStore attestation data is in the certificate as a special extension
  // Now let's look for the challenge in AuthorizationList in the certificate
  // The challenge may be embedded in various places in the certificate

  // First, let's dump the raw certificate data for analysis
  const certHex = attestationCert.raw.toString('hex');

  // Look for the challenge in the raw certificate data
  const challengeHex = Buffer.from(expectedChallenge).toString('hex');

  if (certHex.includes(challengeHex)) {
    console.log('Found challenge in raw certificate data!');
    console.log(`Challenge verified: ${expectedChallenge}`);
    return { verified: true, message: 'Challenge found in certificate data' };
  }

  throw new Error('Challenge not found in attestation certificate');
};

/**
 * 3.
 * Obtain a reference to the X.509 certificate chain parsing and validation library that is most appropriate for your toolset.
 * Verify that the root public certificate is trustworthy and that each certificate signs the next certificate in the chain.
 * @param x509Chain - The chain of {@link X509Certificate} certificates.
 * @throws {Error} - If the chain is invalid.
 */
const validateIssuance = (x509Chain: X509Certificate[]) => {
  if (x509Chain.length === 0) throw new Error('No certificates provided');

  // Check dates
  const now = new Date();
  const datesValid = x509Chain.every(
    (c) => new Date(c.validFrom) < now && now < new Date(c.validTo)
  );
  if (!datesValid) throw new Error('Certificates expired');

  // Check that each certificate, except for the last, is issued by the subsequent one.
  if (x509Chain.length >= 2) {
    for (let i = 0; i < x509Chain.length - 1; i++) {
      const subject = x509Chain[i];
      const issuer = x509Chain[i + 1];

      if (
        !subject ||
        !issuer ||
        subject.checkIssued(issuer) === false ||
        subject.verify(issuer.publicKey) === false
      ) {
        throw new Error('Certificate chain is invalid');
      }
    }
  }

  // Ensure that the last certificate in the chain is the expected Google Hardware Attestation Root CA.
  const pkFile = fs.readFileSync(
    require('path').resolve(__dirname, 'googleHardwareAttestationRoot.key')
  );
  const pk = crypto.createPublicKey(pkFile);
  const rootCert = x509Chain[x509Chain.length - 1]; // Last certificate in the chain is the root certificate
  if (!rootCert || !rootCert.verify(pk)) {
    throw new Error(
      'Root certificate is not signed by Google Hardware Attestation Root CA'
    );
  }
};

/**
 * 4.
 * Check each certificate's revocation status to ensure that none of the certificates have been revoked.
 * @param x509Chain - The chain of {@link X509Certificate} certificates.
 * @throws {Error} - If any certificate in the chain is revoked.
 */
const validateRevokation = async (x509Chain: X509Certificate[]) => {
  if (x509Chain.length === 0) throw new Error('No certificates provided');
  const res = await fetch(CRL_URL, { method: 'GET' });
  if (!res.ok) throw new Error('Failed to fetch CRL');
  const crl = (await res.json()) as CRL; // Add type assertion for crl
  const isExpired = x509Chain.some((cert) => {
    return cert.serialNumber in crl.entries;
  });
  if (isExpired) throw new Error('Certificate is revoked');
};

/**
 * 6.
 * Obtain a reference to the ASN.1 parser library that is most appropriate for your toolset.
 * Find the nearest certificate to the root that contains the key attestation certificate extension.
 *  If the provisioning information certificate extension was present, the key attestation certificate extension must be in the immediately subsequent certificate.
 *  Use the parser to extract the key attestation certificate extension data from that certificate.
 * @param x509Chain - The chain of {@link X509Certificate} certificates.
 * @throws {Error} - If no key attestation extension is found.
 */
const validateKeyAttestationExtension = (x509Chain: X509Certificate[]) => {
  if (x509Chain.length === 0) throw new Error('No certificates provided');
  const found = [...x509Chain].reverse().some((certificate) => {
    const asn1 = asn1js.fromBER(certificate.raw);
    const parsedCertificate = new pkijs.Certificate({ schema: asn1.result });
    const extension = parsedCertificate.extensions?.find(
      (e) => e.extnID === KEY_OID
    );
    return extension ?? false;
  });
  if (!found) throw new Error('No key attestation extension found');
};

const base64ToPem = (b64cert: string) => {
  return (
    '-----BEGIN CERTIFICATE-----\n' +
    b64cert +
    (b64cert.endsWith('\n') ? '' : '\n') +
    '-----END CERTIFICATE-----'
  );
};
