# VerifyBlind iOS SDK

VerifyBlind kimlik doğrulama (PoP Mode — Proof of Personhood) için iOS SDK'sı.
Android `sdk-android` ile **bire bir protokol ve kripto paritesinde** Swift port'u.

> Bağımlılık yok — yalnızca Apple framework'leri (`Foundation`, `CryptoKit`, `Security`, `UIKit`).
> Dağıtım: **Swift Package Manager**.

## Kurulum (Swift Package Manager)

Xcode → *File ▸ Add Package Dependencies…* → bu repo URL'si.
Ya da `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/<org>/sdk-ios.git", from: "2.0.0")
]
```

Minimum dağıtım hedefi: **iOS 13**.

## Kullanım

```swift
import VerifyBlind

let sdk = VerifyBlindSDK(
    config: VerifyBlindConfig(
        partnerBackendUrl: "https://partner.example.com/api/auth",
        generateEndpoint: "generate"
        // verifyblindAppLinkBase / verifyblindApiUrl üretim varsayılanlarını kullanır
    )
)

// 1) Akışı başlat (Universal Link otomatik açılır)
let result = try await sdk.startAuthentication(
    validations: ["age_over": 18]
)

// 2) Kullanıcı VerifyBlind app'inde onayladıktan sonra sonucu poll et
//    (UI tarafında periyodik çağır; nil = henüz beklemede)
if let data = try await sdk.checkVerificationResult(nonce: result.nonce) {
    print("Doğrulandı:", data)
}
```

İptal durumunda `checkVerificationResult` bir `VerifyBlindError` fırlatır
(`code == .userCancelled`, `cancelReason` ile sebep kodu).

## Protokol (Android ile aynı)

1. Cihazda **ephemeral RSA-OAEP-2048** keypair üretilir (yazılım anahtarı).
2. Public key **SPKI** (Base64) olarak partner backend proxy'ye `{ public_key, validations }` gönderilir → `{ nonce }`.
3. `pk_hash = SHA256(publicKeyBase64)` (lowercase hex).
4. Universal Link açılır: `https://app.verifyblind.com/request?nonce=...&pk_hash=...`
5. Relay `GET /api/pop/result/{nonce}` poll edilir; şifreli yanıt **lokalde** çözülür:
   - `enc_key`: RSA-OAEP-**SHA256**/MGF1-SHA256 ile sarılı (base64) AES anahtarı
   - `blob`: `IV(12) + Ciphertext + Tag(16)` AES-GCM-128

## iOS'a özgü kritik notlar

- **SPKI vs PKCS#1**: iOS `SecKeyCopyExternalRepresentation` PKCS#1 döndürür; SDK bunu
  ASN.1 SPKI header'ı ile sarar (`Crypto/SPKI.swift`). Aksi halde `pk_hash` Android/Web ile
  tutmaz ve enclave çözemez.
- **Secure Enclave kullanılmaz**: Secure Enclave RSA desteklemez (yalnızca EC P-256); bu yüzden
  ephemeral RSA anahtarı yazılımda üretilir — Android tarafıyla aynı.
- **Universal Link**: `app.verifyblind.com` üzerinde geçerli bir `apple-app-site-association`
  dosyası ve VerifyBlind iOS uygulamasında *Associated Domains* yetkisi gerekir; aksi halde
  `startAuthentication` Safari'ye düşer.
- **Cihaz bütünlüğü**: `VerifyBlindConfig.integrityTokenProvider` ile App Attest/DeviceCheck
  tabanlı bir sağlayıcı bağlanabilir (Android'deki Play Integrity'nin karşılığı, opsiyonel).
- **Sertifika pinning**: `certificatePins` (OkHttp formatı `sha256/BASE64`) yalnızca partner
  backend'e uygulanır; relay pinlenmez (Android paritesi). RSA ve EC P-256 sunucu anahtarları desteklenir.

## Test

```bash
swift test
```

`Tests/VerifyBlindTests/CryptoParityTests.swift` SPKI sarmalını ve uçtan uca hybrid decrypt
yolunu doğrular. ⚠️ Üretim öncesi gerçek relay'den alınmış bir **golden vector** ile
çapraz-platform parite ayrıca doğrulanmalıdır.
