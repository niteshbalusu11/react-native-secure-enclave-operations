package com.margelo.nitro.secureenclaveoperations
  
import com.facebook.proguard.annotations.DoNotStrip

@DoNotStrip
class SecureEnclaveOperations : HybridSecureEnclaveOperationsSpec() {
  override fun multiply(a: Double, b: Double): Double {
    return a * b
  }
}
