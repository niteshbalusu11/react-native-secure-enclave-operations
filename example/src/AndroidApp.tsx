import { useState } from 'react';
import { View, StyleSheet, Button } from 'react-native';
import {
  isHardwareBackedKeyGenerationSupported,
  generateKey,
  attestKey,
  generateAssertion,
  prepareIntegrityTokenAndroid,
} from 'react-native-secure-enclave-operations';
import { getChallenge, verifyAssertion, verifyAttestation } from './fetch';
const cloudProjectNumber = '25649124009';

export default function AndroidApp() {
  const [generatedKey, setGeneratedKey] = useState('');

  const isAvailable = async () => {
    try {
      const isSupported = await isHardwareBackedKeyGenerationSupported();

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

  const prepareIntegrityToken = async () => {
    try {
      const token = await prepareIntegrityTokenAndroid(cloudProjectNumber);
      console.log('integrity token is ', token);
    } catch (err) {
      console.error('error preparing integrity token', err);
    }
  };

  const attestKeyWithAndroid = async () => {
    try {
      // Generate a unique challenge from server to attest key
      // const challenge = await getChallenge();
      const androidAttestation = await attestKey(
        generatedKey,
        'some challenge'
      );
      console.log('android attestation is ', androidAttestation);

      // await verifyAttestation({
      //   attestation: androidAttestation,
      //   challenge,
      //   keyId: generatedKey,
      // });
    } catch (err) {
      console.error('error attesting with android', err);
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
      <Button onPress={prepareIntegrityToken} title="Prepare integrity token" />
      <Button onPress={attestKeyWithAndroid} title="Attest with Android" />

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
