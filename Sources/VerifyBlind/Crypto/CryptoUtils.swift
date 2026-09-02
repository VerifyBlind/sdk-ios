import Foundation
import CryptoKit
import Security

/// PoP Mode kriptografisi. Android `CryptoUtils.kt` ile bire bir parite:
/// ephemeral RSA-OAEP-2048 keypair, SPKI public key export, `pk_hash = SHA256(base64)`,
/// ve hybrid yanıt çözümü (RSA-OAEP-SHA256 + AES-GCM-128).
enum CryptoUtils {

    /// SHA-256, lowercase hex string (Android `"%02x"` ile aynı).
    static func sha256Hex(_ input: String) -> String {
        let digest = SHA256.hash(data: Data(input.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Ephemeral RSA-OAEP-2048 keypair üretir (yazılım anahtarı — Secure Enclave RSA desteklemez).
    static func generateRsaKeyPair() throws -> (privateKey: SecKey, publicKey: SecKey) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw VerifyBlindError("RSA keypair üretilemedi.",
                                   code: .cryptoError,
                                   underlyingError: error?.takeRetainedValue())
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw VerifyBlindError("RSA public key türetilemedi.", code: .cryptoError)
        }
        return (privateKey, publicKey)
    }

    /// Public key'i Base64 **SPKI** (DER SubjectPublicKeyInfo) olarak verir.
    /// (Web Crypto `"spki"` ve Android `PublicKey.getEncoded()` ile aynı format.)
    static func exportPublicKeyBase64(_ publicKey: SecKey) throws -> String {
        var error: Unmanaged<CFError>?
        guard let pkcs1 = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw VerifyBlindError("Public key dışa aktarılamadı.",
                                   code: .cryptoError,
                                   underlyingError: error?.takeRetainedValue())
        }
        let spki = SPKI.wrapRSA(pkcs1)
        return spki.base64EncodedString()
    }

    /// `pk_hash = SHA-256(publicKeyBase64)` hex string.
    static func computePkHash(_ publicKeyBase64: String) -> String {
        sha256Hex(publicKeyBase64)
    }

    /// Enclave'den gelen hybrid şifreli yanıtı çözer.
    ///
    /// Format:
    /// - `enc_key`: Base64( RSA-OAEP-SHA256( base64(AES key) ) )
    /// - `blob`: Base64( IV(12) + Ciphertext + Tag(16) )   ← WebCrypto/CryptoKit "combined" düzeni
    ///
    /// - Returns: Çözülmüş düz metin (payload + signature içeren JSON string).
    static func decryptHybridResponse(encKey: String, blob: String, privateKey: SecKey) throws -> String {
        // 1) RSA-OAEP-SHA256 ile sarılı AES anahtarını çöz → çıktı: base64(AES key)'in UTF-8 baytları
        guard let encKeyData = Data(base64Encoded: encKey) else {
            throw VerifyBlindError("enc_key Base64 çözülemedi.", code: .cryptoError)
        }
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, .rsaEncryptionOAEPSHA256) else {
            throw VerifyBlindError("RSA-OAEP-SHA256 bu anahtarda desteklenmiyor.", code: .cryptoError)
        }
        var error: Unmanaged<CFError>?
        guard let aesKeyB64Data = SecKeyCreateDecryptedData(
            privateKey, .rsaEncryptionOAEPSHA256, encKeyData as CFData, &error) as Data? else {
            throw VerifyBlindError("AES anahtarı RSA-OAEP ile çözülemedi.",
                                   code: .cryptoError,
                                   underlyingError: error?.takeRetainedValue())
        }

        // Enclave AES anahtarını base64 string olarak şifreliyor — önce string→base64 decode
        guard let aesKeyB64 = String(data: aesKeyB64Data, encoding: .utf8),
              let aesKeyRaw = Data(base64Encoded: aesKeyB64) else {
            throw VerifyBlindError("AES anahtarı Base64 çözülemedi.", code: .cryptoError)
        }

        // 2) AES-GCM çöz — blob: IV(12) + Ciphertext + Tag(16); CryptoKit "combined" ile birebir
        guard let blobData = Data(base64Encoded: blob) else {
            throw VerifyBlindError("blob Base64 çözülemedi.", code: .cryptoError)
        }
        let key = SymmetricKey(data: aesKeyRaw)
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: blobData)
            let plaintext = try AES.GCM.open(sealedBox, using: key)
            guard let str = String(data: plaintext, encoding: .utf8) else {
                throw VerifyBlindError("Çözülen veri UTF-8 değil.", code: .cryptoError)
            }
            return str
        } catch let e as VerifyBlindError {
            throw e
        } catch {
            throw VerifyBlindError("AES-GCM çözme başarısız.", code: .cryptoError, underlyingError: error)
        }
    }
}
