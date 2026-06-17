import Foundation

/// VerifyBlind iOS SDK Konfigürasyonu (PoP Mode — Proof of Personhood).
///
/// Partner backend yalnızca API key ile proxy görevi görür; private key tutmaz.
/// Ephemeral RSA keypair istemcide (cihazda) üretilir.
///
/// Android `VerifyBlindConfig` ile bire bir paritededir.
public struct VerifyBlindConfig {

    /// Partner'ın backend base URL'si (proxy endpoint'i).
    /// Örnek: `"https://partner.example.com/api/auth"`
    public let partnerBackendUrl: String

    /// İşlem başlatma uç noktası (relative path). `partnerBackendUrl` değerine eklenir.
    /// Varsayılan `"."` → Base URL'in kendisi. Örnek: `"generate"`
    public let generateEndpoint: String

    /// VerifyBlind deep link (Universal Link) base URL.
    /// Varsayılan: `"https://app.verifyblind.com/request"`
    public let verifyblindAppLinkBase: String

    /// VerifyBlind relay API URL'si (sonuç polling için).
    /// Varsayılan: `"https://api.verifyblind.com"`
    public let verifyblindApiUrl: String

    /// UYARI: Yalnızca geliştirme/test ortamı içindir. `true` olduğunda Certificate
    /// Pinning devre dışı bırakılır. ÜRETİMDE ASLA `true` KULLANMAYIN.
    public let skipSecurityChecks: Bool

    /// Partner backend için SPKI SHA-256 pin'leri. OkHttp ile aynı format:
    /// `"sha256/BASE64..."` ya da çıplak Base64. `nil`/boş ise pinning uygulanmaz.
    public let certificatePins: [String]?

    public init(
        partnerBackendUrl: String,
        generateEndpoint: String = ".",
        verifyblindAppLinkBase: String = "https://app.verifyblind.com/request",
        verifyblindApiUrl: String = "https://api.verifyblind.com",
        skipSecurityChecks: Bool = false,
        certificatePins: [String]? = nil
    ) {
        precondition(!partnerBackendUrl.trimmingCharacters(in: .whitespaces).isEmpty,
                     "partnerBackendUrl boş olamaz.")
        self.partnerBackendUrl = partnerBackendUrl
        self.generateEndpoint = generateEndpoint
        self.verifyblindAppLinkBase = verifyblindAppLinkBase
        self.verifyblindApiUrl = verifyblindApiUrl
        self.skipSecurityChecks = skipSecurityChecks
        self.certificatePins = certificatePins
    }

    /// `generateEndpoint`'i `partnerBackendUrl`'e göre çözümler (Retrofit `@Url` semantiğinin karşılığı).
    var resolvedGenerateUrl: URL? {
        let ep = generateEndpoint.trimmingCharacters(in: .whitespaces)
        if ep.isEmpty || ep == "." {
            return URL(string: partnerBackendUrl)
        }
        // Mutlak URL ise olduğu gibi kullan
        if let abs = URL(string: ep), abs.scheme != nil {
            return abs
        }
        let base = partnerBackendUrl.hasSuffix("/") ? partnerBackendUrl : partnerBackendUrl + "/"
        return URL(string: ep, relativeTo: URL(string: base))?.absoluteURL
    }
}

enum SDKVersion {
    static let value = "2.1.0"
    static var userAgent: String { "ios/\(value)" }
}
