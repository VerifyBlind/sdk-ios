import XCTest
import CryptoKit
import Security
@testable import VerifyBlind

/// Kripto paritesini doğrular: SPKI dışa aktarımı + uçtan uca hybrid decrypt yolu.
///
/// NOT: Bu testler iOS primitifledinin kendi içinde tutarlı çalıştığını kanıtlar
/// (enclave'in şifrelediğini iOS'un çözebildiği). Üretim öncesi, gerçek relay'den
/// üretilmiş bir GOLDEN VECTOR ile çapraz-platform parite ayrıca doğrulanmalıdır.
final class CryptoParityTests: XCTestCase {

    // MARK: pk_hash

    func testPkHashIsLowercaseHexSHA256() {
        // SHA256("abc") bilinen vektör
        let h = CryptoUtils.sha256Hex("abc")
        XCTAssertEqual(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    // MARK: SPKI export

    func testPublicKeyExportIsSPKIWrappingPKCS1() throws {
        let (_, publicKey) = try CryptoUtils.generateRsaKeyPair()

        var error: Unmanaged<CFError>?
        let pkcs1 = SecKeyCopyExternalRepresentation(publicKey, &error)! as Data
        let spkiB64 = try CryptoUtils.exportPublicKeyBase64(publicKey)
        let spki = Data(base64Encoded: spkiB64)!

        // SPKI, PKCS#1 baytlarını sonunda barındırmalı (BIT STRING içeriği)
        XCTAssertTrue(spki.suffix(pkcs1.count) == pkcs1,
                      "SPKI gövdesi orijinal PKCS#1 anahtarını içermeli")
        // RSA OID (1.2.840.113549.1.1.1) header'da bulunmalı
        let rsaOID: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
        XCTAssertTrue(contains(spki, subsequence: rsaOID), "SPKI rsaEncryption OID içermeli")
        // DER SEQUENCE ile başlamalı
        XCTAssertEqual(spki.first, 0x30)
    }

    // MARK: Uçtan uca hybrid decrypt (enclave simülasyonu)

    func testHybridDecryptRoundTrip() throws {
        let (privateKey, publicKey) = try CryptoUtils.generateRsaKeyPair()

        // --- Enclave'in yaptığını taklit et ---
        // 1) AES-256 anahtarı üret, base64 string'ini RSA-OAEP-SHA256 ile sar
        let aesKey = SymmetricKey(size: .bits256)
        let aesKeyB64 = aesKey.withUnsafeBytes { Data($0) }.base64EncodedString()

        var error: Unmanaged<CFError>?
        let encKeyData = SecKeyCreateEncryptedData(
            publicKey, .rsaEncryptionOAEPSHA256, Data(aesKeyB64.utf8) as CFData, &error)! as Data
        let encKeyB64 = encKeyData.base64EncodedString()

        // 2) Payload'ı AES-GCM ile şifrele → blob = IV(12)+CT+Tag(16) (combined)
        let plaintext = #"{"payload":"{\"verified\":true,\"age_over_18\":true}","signature":"abc"}"#
        let sealed = try AES.GCM.seal(Data(plaintext.utf8), using: aesKey, nonce: AES.GCM.Nonce())
        let blobB64 = sealed.combined!.base64EncodedString()

        // --- SDK çözer ---
        let decrypted = try CryptoUtils.decryptHybridResponse(
            encKey: encKeyB64, blob: blobB64, privateKey: privateKey)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testDecryptRejectsTamperedBlob() throws {
        let (privateKey, publicKey) = try CryptoUtils.generateRsaKeyPair()
        let aesKey = SymmetricKey(size: .bits256)
        let aesKeyB64 = aesKey.withUnsafeBytes { Data($0) }.base64EncodedString()
        var error: Unmanaged<CFError>?
        let encKeyB64 = (SecKeyCreateEncryptedData(
            publicKey, .rsaEncryptionOAEPSHA256, Data(aesKeyB64.utf8) as CFData, &error)! as Data)
            .base64EncodedString()

        let sealed = try AES.GCM.seal(Data("secret".utf8), using: aesKey, nonce: AES.GCM.Nonce())
        var tampered = sealed.combined!
        tampered[tampered.count - 1] ^= 0xFF // tag'i boz

        XCTAssertThrowsError(try CryptoUtils.decryptHybridResponse(
            encKey: encKeyB64, blob: tampered.base64EncodedString(), privateKey: privateKey))
    }

    // MARK: helpers

    private func contains(_ data: Data, subsequence: [UInt8]) -> Bool {
        guard !subsequence.isEmpty, data.count >= subsequence.count else { return false }
        let bytes = [UInt8](data)
        for i in 0...(bytes.count - subsequence.count) where Array(bytes[i..<i+subsequence.count]) == subsequence {
            return true
        }
        return false
    }
}
