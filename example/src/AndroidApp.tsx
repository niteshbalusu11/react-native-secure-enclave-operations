import { View, StyleSheet, Button } from 'react-native';
import {
  isPlayServicesAvailableAndroid,
  getAttestationAndroid,
  requestIntegrityTokenAndroid,
  prepareIntegrityTokenAndroid,
} from 'react-native-secure-enclave-operations';
import uuid from 'react-native-uuid';

import {
  getChallenge,
  verifyAndroidIntegrityToken,
  verifyAndroidAttestation,
} from './fetch';
const cloudProjectNumber = '25649124009';

export default function AndroidApp() {
  const isAvailable = async () => {
    try {
      const isSupported = await isPlayServicesAvailableAndroid();

      console.log('is play services available', isSupported);
    } catch (err) {
      console.error('is play services available error', err);
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

  const requestIntegrityFromAndroid = async () => {
    try {
      // Generate a unique challenge from server to attest key
      const challenge = await getChallenge();

      const androidAttestation = await requestIntegrityTokenAndroid(challenge);

      console.log('android attestation is ', androidAttestation);

      await verifyAndroidIntegrityToken({
        integrityToken: androidAttestation,
      });
    } catch (err) {
      console.error('error attesting with android', err);
    }
  };

  const getHardwareAttestation = async () => {
    try {
      // Generate another challenge for subsequent assertions
      const challenge = await getChallenge();

      const attestation = await getAttestationAndroid(challenge, uuid.v4());
      console.log('assertion result is ', attestation);

      // Verify assertion
      await verifyAndroidAttestation({
        attestation,
      });
    } catch (err) {
      console.error('error generating assertion', err);
    }
  };
  return (
    <View style={styles.container}>
      <Button onPress={isAvailable} title="Is play services available" />
      <Button onPress={prepareIntegrityToken} title="Prepare integrity token" />
      <Button
        onPress={requestIntegrityFromAndroid}
        title="Request integrity from Android"
      />

      <Button onPress={getHardwareAttestation} title="getHardwareAttestation" />
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
