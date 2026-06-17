import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// VerifyBlind iOS SDK — PoP Mode (Proof of Personhood).
///
/// ## Akış
/// 1. `startAuthentication()` → Cihazda ephemeral RSA-OAEP keypair üretir.
/// 2. Partner backend proxy'ye `{ public_key, validations }` gönderir → `{ nonce }` alır.
/// 3. `pk_hash = SHA256(publicKeyBase64)` hesaplar.
/// 4. VerifyBlind Universal Link açılır: `https://app.verifyblind.com/request?nonce=...&pk_hash=...`
/// 5. `checkVerificationResult()` → VerifyBlind relay'i poll eder → şifreli yanıtı lokal çözer.
///
/// ## Kullanım
/// ```swift
/// let sdk = VerifyBlindSDK(
///     config: VerifyBlindConfig(partnerBackendUrl: "https://partner.example.com/api/auth/generate")
/// )
///
/// let result = try await sdk.startAuthentication()
/// // result.nonce, result.pkHash — Universal Link otomatik açıldı
///
/// // Kullanıcı VerifyBlind app'ı onayladıktan sonra (poll):
/// let data = try await sdk.checkVerificationResult(nonce: result.nonce)
/// ```
///
/// Android `VerifyBlindAndroidSDK` ile bire bir parite (Context yerine iOS'ta `UIApplication` global'i kullanılır).
public final class VerifyBlindSDK {

    private let config: VerifyBlindConfig
    private let network: NetworkClient

    /// Ephemeral private key — `startAuthentication`'dan `checkVerificationResult`'a aktarılır.
    private var currentPrivateKey: SecKey?

    public init(config: VerifyBlindConfig) {
        self.config = config
        self.network = NetworkClient(config: config)
    }

    /// VerifyBlind kimlik doğrulama akışını başlatır (PoP Mode).
    ///
    /// - Parameters:
    ///   - validations: İsteğe bağlı doğrulama parametreleri (yaş, uyruk vb.).
    ///   - customData: İsteğe bağlı ek veriler.
    /// - Returns: `nonce` ve `pkHash` içeren `StartAuthResult`.
    /// - Throws: `VerifyBlindError`.
    @discardableResult
    public func startAuthentication(validations: [String: Any]? = nil,
                                    customData: [String: Any]? = nil) async throws -> StartAuthResult {

        // 1. Ephemeral RSA-OAEP keypair
        let (privateKey, publicKey) = try CryptoUtils.generateRsaKeyPair()
        self.currentPrivateKey = privateKey

        // 2. Public key → Base64 SPKI + pk_hash
        let publicKeyBase64 = try CryptoUtils.exportPublicKeyBase64(publicKey)
        let pkHash = CryptoUtils.computePkHash(publicKeyBase64)

        // 3. Cihaz bütünlüğü kanıtı (opsiyonel — App Attest/DeviceCheck sağlayıcısı varsa)
        var integrityToken: String?
        if let provider = config.integrityTokenProvider {
            do {
                integrityToken = try await provider()
            } catch {
                if !config.skipSecurityChecks {
                    throw VerifyBlindError("Cihaz bütünlüğü kanıtı üretilemedi: \(error.localizedDescription)",
                                           code: .cryptoError, underlyingError: error)
                }
            }
        }

        // 4. Partner backend proxy → { nonce }
        let nonce = try await network.startAuth(publicKeyBase64: publicKeyBase64,
                                                integrityToken: integrityToken,
                                                validations: validations,
                                                customData: customData)

        // 5. VerifyBlind Universal Link aç
        try await openAppLink(nonce: nonce, pkHash: pkHash)

        return StartAuthResult(nonce: nonce, pkHash: pkHash, validations: validations)
    }

    /// VerifyBlind relay'i poll ederek sonucu sorgular. Tamamlanmışsa şifreli yanıtı lokal çözer.
    ///
    /// - Returns: Tamamlanmışsa çözülmüş `[String: Any]`, henüz beklemedeyse `nil`.
    /// - Throws: İptal (`userCancelled`) veya kripto hatalarında `VerifyBlindError`.
    public func checkVerificationResult(nonce: String) async throws -> [String: Any]? {
        guard let privateKey = currentPrivateKey else {
            // startAuthentication çağrılmamış → güvenli şekilde nil
            return nil
        }

        guard let body = try await network.getPopResult(nonce: nonce) else {
            return nil
        }

        let status = body.status ?? ""

        if status == "cancelled" {
            let reason = body.reason ?? "user_cancelled"
            let msg: String
            switch reason {
            case "no_card_registered":
                msg = "Kullanıcının VerifyBlind uygulamasında kayıtlı kimlik kartı yok. Önce uygulamaya kimliğini eklemesi gerekiyor."
            case "user_declined":
                msg = "Kullanıcı doğrulama isteğini reddetti."
            case "fingerprint_failed":
                msg = "Parmak izi / biyometrik doğrulama başarısız oldu."
            case "session_expired":
                msg = "Mobil oturum süresi doldu. Yeni QR ile tekrar deneyin."
            default:
                msg = "Kullanıcı kimlik doğrulamayı iptal etti."
            }
            throw VerifyBlindError(msg, code: .userCancelled, cancelReason: reason)
        }

        guard status == "completed" || status == "SUCCESS" else {
            return nil // henüz tamamlanmadı
        }

        guard let encrypted = body.encrypted_response else {
            return nil // completed ama şifreli veri yok
        }

        // Lokal decrypt
        let plaintext = try CryptoUtils.decryptHybridResponse(
            encKey: encrypted.enc_key,
            blob: encrypted.blob,
            privateKey: privateKey
        )

        // { payload: "...", signature: "..." } → payload'ı parse et
        let payloadStr = Self.extractPayload(from: plaintext)
        guard let payloadData = payloadStr.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw VerifyBlindError("Çözülen payload JSON değil.", code: .invalidResponse)
        }
        return obj
    }

    // MARK: - Private

    private static func extractPayload(from plaintext: String) -> String {
        guard let data = plaintext.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let payload = root["payload"] as? String,
              !payload.isEmpty else {
            return plaintext
        }
        return payload
    }

    /// VerifyBlind Mobile uygulamasını Universal Link ile açar.
    /// URL: `https://app.verifyblind.com/request?nonce={nonce}&pk_hash={pkHash}`
    /// Uygulama yüklüyse onu, değilse Safari'yi açar (Android'in app→browser fallback'inin karşılığı).
    private func openAppLink(nonce: String, pkHash: String) async throws {
        var baseStr = config.verifyblindAppLinkBase
        while baseStr.hasSuffix("/") { baseStr.removeLast() }
        if !baseStr.hasSuffix("/request") { baseStr += "/request" }

        guard var components = URLComponents(string: baseStr) else {
            throw VerifyBlindError("App Link URL'si geçersiz.", code: .appLinkFailed)
        }
        components.queryItems = [
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "pk_hash", value: pkHash)
        ]
        guard let url = components.url else {
            throw VerifyBlindError("App Link URL'si oluşturulamadı.", code: .appLinkFailed)
        }

        #if canImport(UIKit)
        let opened = await openURL(url)
        if !opened {
            throw VerifyBlindError("VerifyBlind uygulaması veya tarayıcı açılamadı.", code: .appLinkFailed)
        }
        #else
        throw VerifyBlindError("Universal Link açma yalnızca iOS'ta desteklenir.", code: .appLinkFailed)
        #endif
    }

    #if canImport(UIKit)
    @MainActor
    private func openURL(_ url: URL) async -> Bool {
        let app = UIApplication.shared
        // Önce yalnızca uygulamada aç (universalLinksOnly); yüklü değilse Safari'ye düş
        let openedInApp = await app.open(url, options: [.universalLinksOnly: true])
        if openedInApp { return true }
        return await app.open(url, options: [:])
    }
    #endif
}
