import { NitroModules } from 'react-native-nitro-modules';
import type { SecureEnclaveOperations } from './SecureEnclaveOperations.nitro';

const SecureEnclaveOperationsHybridObject =
  NitroModules.createHybridObject<SecureEnclaveOperations>('SecureEnclaveOperations');

export function multiply(a: number, b: number): number {
  return SecureEnclaveOperationsHybridObject.multiply(a, b);
}
