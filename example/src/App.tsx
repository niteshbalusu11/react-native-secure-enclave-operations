import { useState } from 'react';
import { View, StyleSheet, Button } from 'react-native';
import {
  isAttestationSupported,
  generateKey,
  attestKey,
  generateAssertion,
} from 'react-native-secure-enclave-operations';
import { getChallenge, verifyAssertion, verifyAttestation } from './fetch';

export default function App() {
  const [generatedKey, setGeneratedKey] = useState('');

  const isAvailable = async () => {
    try {
      const isSupported = await isAttestationSupported();

      console.log('is available', isSupported);
    } catch (err) {
      console.error('is available error', err);
    }
  };
  const generateKeyPair = async () => {
    try {
      const key = await generateKey();
      console.log(key);
      setGeneratedKey(key);
    } catch (err) {
      console.error('error generating key pair', err);
    }
  };

  const attestKeyWithApple = async () => {
    try {
      // Generate a unique challenge from server to attest key
      const challenge = await getChallenge();
      const appleAttestation = await attestKey(generatedKey, challenge);
      console.log('apple attestation is ', appleAttestation);

      await verifyAttestation({
        attestation: appleAttestation,
        challenge,
        keyId: generatedKey,
      });
    } catch (err) {
      console.error('error attesting with apple', err);
    }
  };

  const genAssertion = async () => {
    try {
      // Generate another challenge for subsequent assertions
      const challenge = await getChallenge();

      const message = 'some data to sign';

      const assertion = await generateAssertion(
        generatedKey,
        challenge,
        message
      );
      console.log('assertion result is ', assertion);

      // Verify assertion
      await verifyAssertion({
        assertion,
        challenge,
        keyId: generatedKey,
        message,
      });
    } catch (err) {
      console.error('error generating assertion', err);
    }
  };
  return (
    <View style={styles.container}>
      <Button onPress={isAvailable} title="Is secure hardware available" />
      <Button onPress={generateKeyPair} title="Generate key pair" />

      <Button onPress={attestKeyWithApple} title="Attest with apple" />

      <Button onPress={genAssertion} title="Generate assertion" />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
