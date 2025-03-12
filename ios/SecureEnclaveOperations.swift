import CryptoKit
import DeviceCheck
import Foundation
import NitroModules

class SecureEnclaveOperations: HybridSecureEnclaveOperationsSpec {
  
  // This function is not supported on iOS.
  func prepareIntegrityTokenAndroid(cloudProjectNumber: String) throws -> NitroModules.Promise<Bool> {
    return Promise.async {
      // Create a specific error for unsupported platform functionality
      let platformError = NSError(
        domain: "SecureEnclaveOperations",
        code: -100,
        userInfo: [NSLocalizedDescriptionKey: "Google Play Integrity API is not supported on iOS"]
      )
      
      // Throw the error directly in the async block
      throw platformError
    }
  }
  
  private let service = DCAppAttestService.shared

  public func isHardwareBackedKeyGenerationSupported() throws -> Promise<Bool> {
    return Promise.async {
      return self.service.isSupported
    }
  }

  public func generateKey() throws -> Promise<String> {
    return Promise.async {
      return try await withCheckedThrowingContinuation { continuation in
        self.service.generateKey { keyId, error in
          if let error = error {
            continuation.resume(
              throwing: NSError(
                domain: "SecureEnclaveOperations", code: -1,
                userInfo: [
                  NSLocalizedDescriptionKey:
                    "Error generating key: \(error.localizedDescription)"
                ]))
            return
          }

          guard let keyId = keyId else {
            continuation.resume(
              throwing: NSError(
                domain: "SecureEnclaveOperations", code: -2,
                userInfo: [NSLocalizedDescriptionKey: "No key identifier returned"])
            )
            return
          }

          continuation.resume(returning: keyId)
        }
      }
    }
  }

  public func attestKey(keyId: String, challenge: String) throws -> Promise<String> {
    return Promise.async {
      // Convert challenge to Data
      guard let challengeData = challenge.data(using: .utf8) else {
        throw NSError(
          domain: "SecureEnclaveOperations", code: -3,
          userInfo: [NSLocalizedDescriptionKey: "Invalid challenge string"])
      }

      // Create a SHA256 hash of the challenge
      let challengeHash = Data(SHA256.hash(data: challengeData))

      // Attest the key with Apple's servers
      return try await withCheckedThrowingContinuation { continuation in
        self.service.attestKey(keyId, clientDataHash: challengeHash) {
          attestationObject, error in
          if let error = error {
            continuation.resume(
              throwing: NSError(
                domain: "SecureEnclaveOperations", code: -4,
                userInfo: [
                  NSLocalizedDescriptionKey:
                    "Error attesting key: \(error.localizedDescription)"
                ]))
            return
          }

          guard let attestationObject = attestationObject else {
            continuation.resume(
              throwing: NSError(
                domain: "SecureEnclaveOperations", code: -5,
                userInfo: [
                  NSLocalizedDescriptionKey: "No attestation object returned"
                ]))
            return
          }

          // Convert attestation object to base64 string
          let base64Attestation = attestationObject.base64EncodedString()
          continuation.resume(returning: base64Attestation)
        }
      }
    }
  }

  public func generateAssertion(keyId: String, challenge: String, data: String) throws -> Promise<
    String
  > {
    return Promise.async {
      // Create a dictionary with the data and challenge
      let requestData: [String: Any] = [
        "data": data,
        "challenge": challenge,
      ]

      // Convert the dictionary to JSON data
      guard let jsonData = try? JSONSerialization.data(withJSONObject: requestData) else {
        throw NSError(
          domain: "SecureEnclaveOperations", code: -6,
          userInfo: [NSLocalizedDescriptionKey: "Failed to serialize request data"])
      }

      // Create a SHA256 hash of the JSON data
      let jsonDataHash = Data(SHA256.hash(data: jsonData))

      // Generate the assertion using async/await
      return try await withCheckedThrowingContinuation { continuation in
        self.service.generateAssertion(keyId, clientDataHash: jsonDataHash) {
          assertionObject, error in
          if let error = error {
            continuation.resume(
              throwing: NSError(
                domain: "SecureEnclaveOperations", code: -7,
                userInfo: [
                  NSLocalizedDescriptionKey:
                    "Error generating assertion: \(error.localizedDescription)"
                ]))
            return
          }

          guard let assertionObject = assertionObject else {
            continuation.resume(
              throwing: NSError(
                domain: "SecureEnclaveOperations", code: -8,
                userInfo: [
                  NSLocalizedDescriptionKey: "No assertion object returned"
                ]))
            return
          }

          // Convert assertion object to base64 string
          let base64Assertion = assertionObject.base64EncodedString()
          continuation.resume(returning: base64Assertion)
        }
      }
    }
  }
}
