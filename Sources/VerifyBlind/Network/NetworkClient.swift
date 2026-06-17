import Foundation
import CryptoKit
import Security

/// PoP Mode ağ katmanı. Android `NetworkClient`/`KimlikApiService` karşılığı:
/// - Partner backend proxy'ye POST (`{ public_key, integrity_token?, validations?, custom_data? }` → `{ nonce }`)
/// - VerifyBlind relay'den GET `api/pop/result/{nonce}` (tek seferlik okuma)
///
/// Bağımlılık yok: yalnızca `URLSession`. Partner backend'e opsiyonel SPKI sertifika pinning.
final class NetworkClient {

    private let config: VerifyBlindConfig
    private let partnerSession: URLSession
    private let relaySession: URLSession

    init(config: VerifyBlindConfig) {
        self.config = config

        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 30

        // Relay pinlenmiyor (Android paritesi: relay client düz)
        self.relaySession = URLSession(configuration: cfg)

        let pins = (config.certificatePins ?? [])
            .map { $0.hasPrefix("sha256/") ? String($0.dropFirst("sha256/".count)) : $0 }

        if !config.skipSecurityChecks && !pins.isEmpty {
            // Delegate ayrı nesne → URLSession delegate'i güçlü tutar; NetworkClient'a döngü olmaz.
            let delegate = PinningDelegate(pins: pins)
            self.partnerSession = URLSession(configuration: cfg, delegate: delegate, delegateQueue: nil)
        } else {
            self.partnerSession = URLSession(configuration: cfg)
        }
    }

    deinit {
        // Delegate'li oturumu serbest bırak (delegate referansını kırar)
        partnerSession.finishTasksAndInvalidate()
    }

    // MARK: - Partner backend

    func startAuth(publicKeyBase64: String,
                   integrityToken: String?,
                   validations: [String: Any]?,
                   customData: [String: Any]?) async throws -> String {
        guard let url = config.resolvedGenerateUrl else {
            throw VerifyBlindError("partnerBackendUrl/generateEndpoint geçersiz.", code: .invalidResponse)
        }

        var body: [String: Any] = ["public_key": publicKeyBase64]
        if let integrityToken { body["integrity_token"] = integrityToken }
        if let validations { body["validations"] = validations }
        if let customData { body["custom_data"] = customData }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(SDKVersion.userAgent, forHTTPHeaderField: "X-VerifyBlind-SDK")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await partnerSession.vbData(for: request)
        } catch {
            throw VerifyBlindError("Partner backend'e ulaşılamadı: \(error.localizedDescription)",
                                   code: .networkError, underlyingError: error)
        }

        guard let http = response as? HTTPURLResponse else {
            throw VerifyBlindError("Geçersiz HTTP yanıtı.", code: .invalidResponse)
        }
        guard (200..<300).contains(http.statusCode) else {
            let bodyStr = String(data: data, encoding: .utf8) ?? "Bilinmeyen hata"
            throw VerifyBlindError("Partner backend hatası (\(http.statusCode)): \(bodyStr)",
                                   code: .partnerBackendError)
        }

        let decoded = try? JSONDecoder().decode(PartnerBackendResponse.self, from: data)
        guard let nonce = decoded?.nonce, !nonce.isEmpty else {
            throw VerifyBlindError(
                "Partner backend yanıtında 'nonce' bulunamadı. Proxy'nin { nonce } döndürdüğünden emin olun.",
                code: .invalidResponse)
        }
        return nonce
    }

    // MARK: - Relay polling

    /// `GET api/pop/result/{nonce}`. Henüz hazır değilse `nil` döner.
    func getPopResult(nonce: String) async throws -> PopResultResponse? {
        let base = config.verifyblindApiUrl.hasSuffix("/")
            ? config.verifyblindApiUrl : config.verifyblindApiUrl + "/"
        guard let url = URL(string: "api/pop/result/\(nonce)", relativeTo: URL(string: base)) else {
            throw VerifyBlindError("Relay URL oluşturulamadı.", code: .invalidResponse)
        }
        var request = URLRequest(url: url)
        request.setValue(SDKVersion.userAgent, forHTTPHeaderField: "X-VerifyBlind-SDK")

        let (data, response) = try await relaySession.vbData(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            return nil
        }
        return try? JSONDecoder().decode(PopResultResponse.self, from: data)
    }
}

// MARK: - SPKI public-key pinning (partner backend)

/// Partner backend'e SPKI SHA-256 sertifika pinning uygular (OkHttp `sha256/...` formatıyla aynı).
/// Ayrı nesne — `NetworkClient` ile delegate döngüsünü önler.
final class PinningDelegate: NSObject, URLSessionDelegate {

    private let pins: [String]

    init(pins: [String]) { self.pins = pins }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // 1) Zincir geçerliliği (sistem doğrulaması)
        var err: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &err) else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }

        // 2) Leaf sertifika public key SPKI SHA-256 (Base64) — OkHttp pin formatıyla aynı
        guard let leaf = Self.leafCertificate(serverTrust),
              let publicKey = SecCertificateCopyKey(leaf),
              let spkiHash = Self.spkiSHA256Base64(publicKey) else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }

        if pins.contains(spkiHash) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    private static func leafCertificate(_ trust: SecTrust) -> SecCertificate? {
        if #available(iOS 15.0, *) {
            return (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first
        } else {
            return SecTrustGetCertificateAtIndex(trust, 0)
        }
    }

    private static func spkiSHA256Base64(_ publicKey: SecKey) -> String? {
        guard let attrs = SecKeyCopyAttributes(publicKey) as? [String: Any],
              let keyType = attrs[kSecAttrKeyType as String] as? String else { return nil }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else { return nil }

        let spki: Data
        if keyType == (kSecAttrKeyTypeRSA as String) {
            spki = SPKI.wrapRSA(raw)
        } else if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String), raw.count == 65 {
            spki = SPKI.wrapEC_P256(raw) // 0x04 || X(32) || Y(32)
        } else {
            return nil // desteklenmeyen anahtar tipi → fail-closed
        }
        return Data(SHA256.hash(data: spki)).base64EncodedString()
    }
}

// MARK: - iOS 13/14 için async URLSession köprüsü (built-in data(for:) iOS 15+)

extension URLSession {
    func vbData(for request: URLRequest) async throws -> (Data, URLResponse) {
        if #available(iOS 15.0, *) {
            return try await self.data(for: request, delegate: nil)
        }
        return try await withCheckedThrowingContinuation { continuation in
            let task = self.dataTask(with: request) { data, response, error in
                if let error { continuation.resume(throwing: error); return }
                guard let data, let response else {
                    continuation.resume(throwing: URLError(.badServerResponse)); return
                }
                continuation.resume(returning: (data, response))
            }
            task.resume()
        }
    }
}
