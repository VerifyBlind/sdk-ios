# VerifyBlind iOS SDK

> **Kimliğinizi Kanıtlayın, Gizliliğinizi Koruyun** · _Prove Your Identity, Protect Your Privacy_

**[🇹🇷 Türkçe](#türkçe) · [🇬🇧 English](#english)**

---

## Türkçe

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

### Uygulamanıza geri dönüş (app-to-app)

Kendi uygulamanızdan VerifyBlind'ı açtığınızda bir `returnUrl` geçin; VerifyBlind işlem bitince
(başarı veya iptal) kullanıcıyı **uygulamanıza geri getirir**:

```swift
let result = try await sdk.startAuthentication(
    validations: ["user_id": true],
    returnUrl: "mypartnerapp://callback"   // uygulamanızın özel şeması
)
```

VerifyBlind bitişte `mypartnerapp://callback?nonce={nonce}&status=success` (ya da `status=cancelled`)
açar → uygulamanız öne gelir; ardından `checkVerificationResult` ile sonucu poll edin.

**İki zorunlu adım:**
1. Şemayı **Partner Portal → Ayarlar → Uygulama Geri-Dönüş Şeması**'na kaydedin (ör. `mypartnerapp`).
   VerifyBlind yalnızca şeması kayıtlı değerle **eşleşen** return URL'i açar (fail-closed → açık-yönlendirme
   önlemi). Boş bırakılırsa geri dönüş kapalıdır.
2. Şemayı uygulamanızın `Info.plist`'ine `CFBundleURLTypes` altında ekleyin ve `onOpenURL` ile karşılayın.

> QR (cihazlar-arası) akışlarda `returnUrl` yok sayılır — geri dönülecek çağıran uygulama yoktur.

## Protokol (Android ile aynı)

1. Cihazda **ephemeral RSA-OAEP-2048** keypair üretilir (yazılım anahtarı).
2. Public key **SPKI** (Base64) olarak partner backend proxy'ye `{ public_key, validations }` gönderilir → `{ nonce }`.
3. `pk_hash = SHA256(publicKeyBase64)` (lowercase hex).
4. Universal Link açılır: `https://app.verifyblind.com/request?nonce=...&pk_hash=...`
5. Relay `GET /api/pop/result/{nonce}` poll edilir; şifreli yanıt **lokalde** çözülür:
   - `enc_key`: RSA-OAEP-**SHA256**/MGF1-SHA256 ile sarılı (base64) AES anahtarı
   - `blob`: `IV(12) + Ciphertext + Tag(16)` AES-GCM-128

## Tekillik / Tanıma Kodları

`validations` içinde `user_id: true` isterseniz, çözülen yanıtta (`checkVerificationResult`) **üç kod birden** döner — üçünü de saklayın:

| Alan | Anlam |
|------|-------|
| `user_id` | Ulusal-no bazlı kimlik (TCKN yoksa boş). Partner'a özel HMAC. |
| `nsbd_id` | Biyografik kişi kodu; kişinin tüm kartlarında sabit. **Olasılıksal ipucu** — tek başına sert dedup kararı vermeyin. |
| `doc_id` | Belge kodu; aynı `doc_id` = aynı fiziksel belge = aynı kişi (sert sinyal). |

Üçü de partner'a özeldir (başka partner ile eşleştirilemez) ve TCKN'ye döndürülemez. Üçünü birlikte saklamak, bir ülke ulusal kimlik numarasını sonradan kaldırsa/eklese veya kullanıcı kartını yenilese bile aynı kişiyi tanımanızı sağlar.

## iOS'a özgü kritik notlar

- **SPKI vs PKCS#1**: iOS `SecKeyCopyExternalRepresentation` PKCS#1 döndürür; SDK bunu
  ASN.1 SPKI header'ı ile sarar (`Crypto/SPKI.swift`). Aksi halde `pk_hash` Android/Web ile
  tutmaz ve enclave çözemez.
- **Secure Enclave kullanılmaz**: Secure Enclave RSA desteklemez (yalnızca EC P-256); bu yüzden
  ephemeral RSA anahtarı yazılımda üretilir — Android tarafıyla aynı.
- **Universal Link**: `app.verifyblind.com` üzerinde geçerli bir `apple-app-site-association`
  dosyası ve VerifyBlind iOS uygulamasında *Associated Domains* yetkisi gerekir; aksi halde
  `startAuthentication` Safari'ye düşer.- **Sertifika pinning**: `certificatePins` (OkHttp formatı `sha256/BASE64`) yalnızca partner
  backend'e uygulanır; relay pinlenmez (Android paritesi). RSA ve EC P-256 sunucu anahtarları desteklenir.

## Test

```bash
swift test
```

`Tests/VerifyBlindTests/CryptoParityTests.swift` SPKI sarmalını ve uçtan uca hybrid decrypt
yolunu doğrular. ⚠️ Üretim öncesi gerçek relay'den alınmış bir **golden vector** ile
çapraz-platform parite ayrıca doğrulanmalıdır.

---

## English

The iOS SDK for VerifyBlind identity verification (PoP Mode — Proof of Personhood). A Swift port at
**exact protocol and crypto parity** with the Android `sdk-android`.

> No dependencies — only Apple frameworks (`Foundation`, `CryptoKit`, `Security`, `UIKit`).
> Distribution: **Swift Package Manager**.

### Installation (Swift Package Manager)

Xcode → *File ▸ Add Package Dependencies…* → this repo's URL.
Or in `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/<org>/sdk-ios.git", from: "2.0.0")
]
```

Minimum deployment target: **iOS 13**.

### Usage

```swift
import VerifyBlind

let sdk = VerifyBlindSDK(
    config: VerifyBlindConfig(
        partnerBackendUrl: "https://partner.example.com/api/auth",
        generateEndpoint: "generate"
        // verifyblindAppLinkBase / verifyblindApiUrl use the production defaults
    )
)

// 1) Start the flow (the Universal Link opens automatically)
let result = try await sdk.startAuthentication(
    validations: ["age_over": 18]
)

// 2) After the user confirms in the VerifyBlind app, poll for the result
//    (call periodically from the UI; nil = still pending)
if let data = try await sdk.checkVerificationResult(nonce: result.nonce) {
    print("Verified:", data)
}
```

On cancellation, `checkVerificationResult` throws a `VerifyBlindError`
(`code == .userCancelled`, with the reason in `cancelReason`).

### Returning to your app after verification (app-to-app)

When you launch VerifyBlind from your own app, pass a `returnUrl` so VerifyBlind brings the user **back
to your app** when the flow ends (success or cancel):

```swift
let result = try await sdk.startAuthentication(
    validations: ["user_id": true],
    returnUrl: "mypartnerapp://callback"   // your app's custom scheme
)
```

When done, VerifyBlind opens `mypartnerapp://callback?nonce={nonce}&status=success` (or
`status=cancelled`), foregrounding your app; then resume polling with `checkVerificationResult`.

**Two required steps:**
1. Register the scheme in **Partner Portal → Settings → App Return Scheme** (e.g. `mypartnerapp`).
   VerifyBlind only opens a return URL whose **scheme matches your registered value** (fail-closed —
   prevents open-redirect). Leaving it empty disables app return.
2. Declare the scheme under `CFBundleURLTypes` in your app's `Info.plist` and handle it in `onOpenURL`.

> QR (cross-device) flows ignore `returnUrl` — there is no caller app to return to.

### Protocol (same as Android)

1. An **ephemeral RSA-OAEP-2048** keypair is generated on the device (software key).
2. The public key is sent as **SPKI** (Base64) to the partner backend proxy as `{ public_key, validations }` → `{ nonce }`.
3. `pk_hash = SHA256(publicKeyBase64)` (lowercase hex).
4. The Universal Link opens: `https://app.verifyblind.com/request?nonce=...&pk_hash=...`
5. The relay's `GET /api/pop/result/{nonce}` is polled; the encrypted response is decrypted **locally**:
   - `enc_key`: an AES key wrapped with RSA-OAEP-**SHA256**/MGF1-SHA256 (base64)
   - `blob`: `IV(12) + Ciphertext + Tag(16)` AES-GCM-128

### Uniqueness / Recognition Codes

If you request `user_id: true` inside `validations`, the decrypted response (`checkVerificationResult`)
returns **three codes at once** — store all three:

| Field | Meaning |
|-------|---------|
| `user_id` | National-number-based identity (empty if there is no national number). Partner-specific HMAC. |
| `nsbd_id` | Biographic person code; stable across all of a person's cards. **Probabilistic hint** — don't make a hard dedup decision on it alone. |
| `doc_id` | Document code; the same `doc_id` = the same physical document = the same person (hard signal). |

All three are partner-specific (cannot be correlated with another partner) and cannot be reversed to a
national ID number. Storing all three lets you recognize the same person even if a country later removes
or adds a national ID number, or the user renews their card.

### iOS-specific critical notes

- **SPKI vs PKCS#1**: iOS `SecKeyCopyExternalRepresentation` returns PKCS#1; the SDK wraps it with an
  ASN.1 SPKI header (`Crypto/SPKI.swift`). Otherwise `pk_hash` won't match Android/Web and the enclave
  cannot decrypt.
- **Secure Enclave is not used**: the Secure Enclave doesn't support RSA (only EC P-256), so the
  ephemeral RSA key is generated in software — same as on Android.
- **Universal Link**: requires a valid `apple-app-site-association` file on `app.verifyblind.com` and
  the *Associated Domains* entitlement in the VerifyBlind iOS app; otherwise `startAuthentication` falls
  back to Safari.
- **Certificate pinning**: `certificatePins` (OkHttp format `sha256/BASE64`) applies only to the partner
  backend; the relay is not pinned (Android parity). RSA and EC P-256 server keys are supported.

### Test

```bash
swift test
```

`Tests/VerifyBlindTests/CryptoParityTests.swift` verifies the SPKI wrapping and the end-to-end hybrid
decrypt path. ⚠️ Before production, cross-platform parity must also be verified against a **golden
vector** captured from a real relay.
