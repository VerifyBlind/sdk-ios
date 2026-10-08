import XCTest
@testable import VerifyBlind

/// `token`, web widget'ının onSuccess token'ıyla aynı biçimde olmalı: base64(JSON { payload, signature }).
final class SignedTokenTests: XCTestCase {

    func testSignedAnswerBecomesBase64OfTheRawJson() throws {
        let raw = #"{"payload":"{\"nonce\":\"n1\",\"validations\":{\"age\":true,\"age_condition\":\"18+\"}}","signature":"c2ln"}"#
        let token = try XCTUnwrap(VerifyBlindSDK.signedToken(from: raw))
        let decoded = String(data: try XCTUnwrap(Data(base64Encoded: token)), encoding: .utf8)
        XCTAssertEqual(decoded, raw)
    }

    func testAnswerWithoutSignatureHasNoToken() {
        XCTAssertNil(VerifyBlindSDK.signedToken(from: #"{"payload":"{}"}"#))
        XCTAssertNil(VerifyBlindSDK.signedToken(from: #"{"nonce":"n1"}"#))
        XCTAssertNil(VerifyBlindSDK.signedToken(from: "not json"))
    }
}
