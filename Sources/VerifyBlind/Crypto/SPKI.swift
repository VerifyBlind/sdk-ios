import Foundation

/// Minimal ASN.1 DER yardımcıları.
///
/// iOS `SecKeyCopyExternalRepresentation` bir RSA public key için **PKCS#1**
/// (`RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`) döndürür.
/// Android `PublicKey.getEncoded()` ve Web Crypto `"spki"` export ise **SubjectPublicKeyInfo (SPKI)**
/// döndürür. Enclave/relay SPKI bekler — dolayısıyla iOS tarafında PKCS#1'i SPKI'ye sarmamız ŞART.
enum SPKI {

    /// RSA AlgorithmIdentifier: `SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL }`
    private static let rsaAlgorithmIdentifier: [UInt8] = [
        0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00
    ]

    /// EC AlgorithmIdentifier: `SEQUENCE { OID id-ecPublicKey, OID prime256v1 }` (P-256).
    private static let ecP256AlgorithmIdentifier: [UInt8] = [
        0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,          // id-ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07     // prime256v1
    ]

    /// PKCS#1 RSAPublicKey baytlarını SubjectPublicKeyInfo (SPKI) DER'ine sarar.
    static func wrapRSA(_ pkcs1: Data) -> Data {
        let bitString = derBitString(pkcs1)
        let body = Data(rsaAlgorithmIdentifier) + bitString
        return derSequence(body)
    }

    /// EC P-256 uncompressed point (`0x04 || X || Y`) baytlarını SPKI DER'ine sarar.
    /// (Sertifika pinning'de sunucu anahtarı EC ise kullanılır.)
    static func wrapEC_P256(_ point: Data) -> Data {
        let bitString = derBitString(point)
        return derSequence(Data(ecP256AlgorithmIdentifier) + bitString)
    }

    // MARK: - DER primitifleri

    static func derSequence(_ content: Data) -> Data {
        Data([0x30]) + derLength(content.count) + content
    }

    /// BIT STRING — kullanılmayan bit sayısı (0x00) önek baytı ile.
    static func derBitString(_ content: Data) -> Data {
        Data([0x03]) + derLength(content.count + 1) + Data([0x00]) + content
    }

    static func derLength(_ n: Int) -> Data {
        if n < 0x80 {
            return Data([UInt8(n)])
        }
        var len = n
        var bytes: [UInt8] = []
        while len > 0 {
            bytes.insert(UInt8(len & 0xff), at: 0)
            len >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}
