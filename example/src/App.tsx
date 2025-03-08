import { useState } from 'react';
import { View, StyleSheet, Button } from 'react-native';
import {
  isAttestationSupported,
  generateKey,
  attestKey,
  generateAssertion,
} from 'react-native-secure-enclave-operations';

export default function App() {
  const [generatedKey, setGeneratedKey] = useState('');

  const isAvailable = async () => {
    try {
      const isAvailable = await isAttestationSupported();

      console.log('is available', isAvailable);
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
      const key = await attestKey(generatedKey, 'some challenge');
      console.log('generated pubkey is ', key);
    } catch (err) {
      console.error('error attesting with apple', err);
    }
  };

  const genAssertion = async () => {
    try {
      const res = await generateAssertion(
        generatedKey,
        'some challenge',
        'some data to sign'
      );
      console.log('assertion result is ', res);
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
