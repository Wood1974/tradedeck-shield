import Foundation
import DeviceCheck
import CryptoKit
import Security

actor AppAttestManager {
    private let service = DCAppAttestService.shared
    private func keychainKey(_ accountID: String) -> String { "com.tradedeck.shield.appattest.key-id.\(accountID)" }
    private func attestedKey(_ accountID: String) -> String { "com.tradedeck.shield.appattest.attested.\(accountID)" }

    func isSupported() -> Bool { service.isSupported }

    func ensureAttested(accountID: String, api: ShieldAPI) async throws {
        guard service.isSupported else { throw AttestError.unsupported }
        let key = try await ensureKey(accountID: accountID)
        guard !KeychainStore.exists(attestedKey(accountID)) else { return }
        let challenge = try await api.attestationChallenge(accountID: accountID)
        let clientDataHash = Data(SHA256.hash(data: Data(challenge.nonce.utf8)))
        let attestation = try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data, Error>) in
            service.attestKey(key, clientDataHash: clientDataHash) { data, error in
                if let error { c.resume(throwing: error) }
                else if let data { c.resume(returning: data) }
                else { c.resume(throwing: AttestError.empty) }
            }
        }
        _ = try await api.registerAttestation(accountID: accountID, keyID: key, nonce: challenge.nonce, attestation: attestation)
        KeychainStore.set(attestedKey(accountID), value: "1")
    }

    func assertion(accountID: String, clientDataHash: Data) async throws -> (String, Data) {
        guard service.isSupported else { throw AttestError.unsupported }
        let key = try await ensureKey(accountID: accountID)
        let assertion = try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data, Error>) in
            service.generateAssertion(key, clientDataHash: clientDataHash) { data, error in
                if let error { c.resume(throwing: error) }
                else if let data { c.resume(returning: data) }
                else { c.resume(throwing: AttestError.empty) }
            }
        }
        return (key, assertion)
    }

    private func ensureKey(accountID: String) async throws -> String {
        let keychainKey = keychainKey(accountID)
        if let saved = KeychainStore.get(keychainKey) { return saved }
        let key = try await withCheckedThrowingContinuation { (c: CheckedContinuation<String, Error>) in
            service.generateKey { key, error in
                if let error { c.resume(throwing: error) }
                else if let key { c.resume(returning: key) }
                else { c.resume(throwing: AttestError.noKey) }
            }
        }
        KeychainStore.set(keychainKey, value: key)
        return key
    }

    enum AttestError: Error { case unsupported, empty, noKey }
}

private enum KeychainStore {
    static func get(_ key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func exists(_ key: String) -> Bool { get(key) != nil }

    static func set(_ key: String, value: String) {
        let data = Data(value.utf8)
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }
}
