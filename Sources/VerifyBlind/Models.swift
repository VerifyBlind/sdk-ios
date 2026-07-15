import Foundation

/// VerifyBlind işlemi başlatma sonucu.
///
/// - `nonce`: API'ye kaydedilen nonce; Universal Link URL'sinde kullanılır.
/// - `pkHash`: Ephemeral public key hash'i; Universal Link URL'sinde kullanılır.
public struct StartAuthResult {
    public let nonce: String
    public let pkHash: String
    public let validations: [String: Any]?

    init(nonce: String, pkHash: String, validations: [String: Any]?) {
        self.nonce = nonce
        self.pkHash = pkHash
        self.validations = validations
    }
}

// MARK: - Wire (Codable) modelleri

/// VerifyBlind relay'den poll sonucu. `GET /api/pop/result/{nonce}`.
struct PopResultResponse: Decodable {
    let status: String?
    let encrypted_response: EncryptedResponsePayload?
    let error: String?
    /// İptal durumunda partnere bildirilen sebep kodu.
    let reason: String?
}

/// Enclave'den gelen hybrid şifreli yanıt.
struct EncryptedResponsePayload: Decodable {
    let enc_key: String
    let blob: String
}

/// Partner backend proxy yanıtı (PoP Mode). Proxy `{ public_key, validations }`
/// alır, VerifyBlind API'ye iletir, `{ nonce }` döndürür.
struct PartnerBackendResponse: Decodable {
    let nonce: String?
    let error: String?
}
