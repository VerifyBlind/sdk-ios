import Foundation

/// VerifyBlind SDK tarafından fırlatılan hata tipi.
/// Android `VerifyBlindException` ile aynı hata kodlarını taşır.
public struct VerifyBlindError: Error, LocalizedError {

    public enum Code: String, Sendable {
        /// Cihazın dış IP adresi alınamadı
        case ipFetchFailed = "IP_FETCH_FAILED"
        /// Partner backend'e ağ hatası nedeniyle ulaşılamadı
        case networkError = "NETWORK_ERROR"
        /// Partner backend hata yanıtı döndürdü
        case partnerBackendError = "PARTNER_BACKEND_ERROR"
        /// Partner backend yanıtı beklenen formatta değil (nonce eksik)
        case invalidResponse = "INVALID_RESPONSE"
        /// App Link / Universal Link açılamadı (VerifyBlind uygulaması yüklü değil?)
        case appLinkFailed = "APP_LINK_FAILED"
        /// Kullanıcı kimlik doğrulamayı iptal etti (consent veya biyometrik adımında)
        case userCancelled = "USER_CANCELLED"
        /// Kriptografik işlem başarısız (anahtar üretimi/çözme)
        case cryptoError = "CRYPTO_ERROR"
        /// Bilinmeyen hata
        case unknown = "UNKNOWN"
    }

    public let message: String
    public let code: Code
    public let underlyingError: Error?

    /// `userCancelled` durumunda partnere bildirilen sebep kodu.
    /// Olası değerler: `user_cancelled`, `no_card_registered`, `user_declined`,
    /// `fingerprint_failed`, `session_expired`. Geriye dönük uyumluluk için
    /// bilinmeyen değerleri `user_cancelled` gibi ele alın.
    public let cancelReason: String?

    public init(_ message: String,
                code: Code = .unknown,
                cancelReason: String? = nil,
                underlyingError: Error? = nil) {
        self.message = message
        self.code = code
        self.cancelReason = cancelReason
        self.underlyingError = underlyingError
    }

    public var errorDescription: String? { message }
}
