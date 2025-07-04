///
/// HybridSecureEnclaveOperationsSpec.cpp
/// This file was generated by nitrogen. DO NOT MODIFY THIS FILE.
/// https://github.com/mrousavy/nitro
/// Copyright © 2025 Marc Rousavy @ Margelo
///

#include "HybridSecureEnclaveOperationsSpec.hpp"

namespace margelo::nitro::secureenclaveoperations {

  void HybridSecureEnclaveOperationsSpec::loadHybridMethods() {
    // load base methods/properties
    HybridObject::loadHybridMethods();
    // load custom methods/properties
    registerHybrids(this, [](Prototype& prototype) {
      prototype.registerHybridMethod("isHardwareBackedKeyGenerationSupportedIos", &HybridSecureEnclaveOperationsSpec::isHardwareBackedKeyGenerationSupportedIos);
      prototype.registerHybridMethod("generateKeyIos", &HybridSecureEnclaveOperationsSpec::generateKeyIos);
      prototype.registerHybridMethod("attestKeyIos", &HybridSecureEnclaveOperationsSpec::attestKeyIos);
      prototype.registerHybridMethod("generateAssertionIos", &HybridSecureEnclaveOperationsSpec::generateAssertionIos);
      prototype.registerHybridMethod("isPlayServicesAvailableAndroid", &HybridSecureEnclaveOperationsSpec::isPlayServicesAvailableAndroid);
      prototype.registerHybridMethod("prepareIntegrityTokenAndroid", &HybridSecureEnclaveOperationsSpec::prepareIntegrityTokenAndroid);
      prototype.registerHybridMethod("requestIntegrityTokenAndroid", &HybridSecureEnclaveOperationsSpec::requestIntegrityTokenAndroid);
      prototype.registerHybridMethod("getAttestationAndroid", &HybridSecureEnclaveOperationsSpec::getAttestationAndroid);
    });
  }

} // namespace margelo::nitro::secureenclaveoperations
