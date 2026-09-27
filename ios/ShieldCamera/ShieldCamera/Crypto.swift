import Foundation
import CryptoKit

func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

// Shield Evidence Core v1:
// SHA-256(photoHash || noteHash || jobId || pointId || nonce || accountId)
// Direct UTF-8 concatenation. No separators or length prefixes.
func bindPayload(photo: String, note: String, job: String, point: String, nonce: String, account: String) -> Data {
    Data((photo + note + job + point + nonce + account).utf8)
}

func bindHash(photo: String, note: String, job: String, point: String, nonce: String, account: String) -> String {
    sha256Hex(bindPayload(photo: photo, note: note, job: job, point: point, nonce: nonce, account: account))
}

func canonicalNote(locationStated:String,purpose:String)->Data {
    let location=locationStated.trimmingCharacters(in:.whitespacesAndNewlines)
    let why=purpose.trimmingCharacters(in:.whitespacesAndNewlines)
    // JSONSerialization with sortedKeys produces the v1 key order: location_stated,purpose.
    return try! JSONSerialization.data(withJSONObject:["location_stated":location,"purpose":why],options:[.sortedKeys,.withoutEscapingSlashes])
}
