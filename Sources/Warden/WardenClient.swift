//
//  WardenClient.swift
//  warden-ios
//
//  Created by Carlos Petit on 23-10-25.
//

import Foundation
import AuthenticationServices

public struct WardenConfig {
    public let apiKey: String
    public let apiBaseUrl: String
    /// Origin del Relying Party (ej: https://warden-demo-ios.app)
    public let rpOrigin: String

    public init(apiKey: String, apiBaseUrl: String, rpOrigin: String) {
        self.apiKey = apiKey
        self.apiBaseUrl = apiBaseUrl
        self.rpOrigin = rpOrigin
    }
}

public struct RegisterResult: Decodable {
    public let verified: Bool
}

public struct LoginResult: Decodable {
    public let verified: Bool
    public let user: User?
    public struct User: Decodable {
        public let id: String
        public let username: String
    }
}

public final class WardenError: NSError, @unchecked Sendable {
    public init(_ message: String, status: Int? = nil) {
        super.init(domain: "WardenError", code: status ?? -1, userInfo: [NSLocalizedDescriptionKey: message])
    }
    required init?(coder: NSCoder) { fatalError() }
}

@MainActor
public final class WardenClient: NSObject {
    public static let shared = WardenClient()
    private override init() {}

    private var config: WardenConfig?

    // MARK: - Public API
    public func configure(_ config: WardenConfig) {
        self.config = config
    }

    public var isConfigured: Bool {
        guard let c = config else { return false }
        return !c.apiKey.isEmpty && !c.apiBaseUrl.isEmpty && !c.rpOrigin.isEmpty
    }

    /// Llama a /passkey/register-options → inicia flujo de Passkey → POST /passkey/verify-registration
    public func register(email: String, presentingAnchor: ASPresentationAnchor) async throws -> RegisterResult {
        try assertConfigured()

        struct RegisterOptionsEnvelope: Decodable {
            let options: PublicKeyCredentialCreationOptions
            let tempToken: String
        }

        // Agregamos origin en query y header (robusto para cualquier backend)
        let encodedEmail = email.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? email
        let encodedOrigin = try encodedRpOriginQueryParam()

        let env: RegisterOptionsEnvelope = try await getJson(
            path: "/passkey/register-options?username=\(encodedEmail)&origin=\(encodedOrigin)"
        )

        let rpId = env.options.rp.id
        let challenge = try Data(base64url: env.options.challenge)
        let userID = try Data(base64url: env.options.user.id)
        let userName = env.options.user.name

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: userName,
            userID: userID
        )
        // request.userVerificationPreference = .preferred

        let registration = try await performAuthorization(requests: [request], anchor: presentingAnchor)

        guard let reg = registration as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            throw WardenError("Respuesta de registro inválida")
        }

        // Empaquetar respuesta para tu backend (formato WebAuthn JSON)
        let payload: [String: Any] = [
            "tempToken": env.tempToken,
            "registrationResponse": [
                "id": reg.credentialID.base64urlString,
                "rawId": reg.credentialID.base64urlString,
                "response": [
                    "attestationObject": reg.rawAttestationObject?.base64urlString ?? "",
                    "clientDataJSON": reg.rawClientDataJSON.base64urlString
                ],
                "type": "public-key",
            ]
        ]

        return try await postJson(path: "/passkey/verify-registration", body: payload)
    }

    /// Llama a /passkey/login-options → inicia flujo → POST /passkey/verify-login
    public func login(presentingAnchor: ASPresentationAnchor) async throws -> LoginResult {
        try assertConfigured()

        struct LoginOptionsEnvelope: Decodable {
            let options: PublicKeyCredentialRequestOptions
            let tempToken: String
        }

        let encodedOrigin = try encodedRpOriginQueryParam()
        let env: LoginOptionsEnvelope = try await getJson(
            path: "/passkey/login-options?origin=\(encodedOrigin)"
        )

        let rpId = env.options.rpId ?? env.options.rp?.id ?? ""
        let challenge = try Data(base64url: env.options.challenge)

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
        let request = provider.createCredentialAssertionRequest(challenge: challenge)

        if let allow = env.options.allowCredentials, !allow.isEmpty {
            request.allowedCredentials = allow.compactMap { cred in
                guard let id = try? Data(base64url: cred.id) else { return nil }
                return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: id)
            }
        }
        // request.userVerificationPreference = .preferred

        let assertion = try await performAuthorization(requests: [request], anchor: presentingAnchor)

        guard let auth = assertion as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            throw WardenError("Respuesta de login inválida")
        }

        let payload: [String: Any] = [
            "tempToken": env.tempToken,
            "authenticationResponse": [
                "id": auth.credentialID.base64urlString,
                "rawId": auth.credentialID.base64urlString,
                "type": "public-key",
                "response": [
                    "authenticatorData": auth.rawAuthenticatorData.base64urlString,
                    "clientDataJSON": auth.rawClientDataJSON.base64urlString,
                    "signature": auth.signature.base64urlString,
                    "userHandle": (auth.userID.isEmpty ? "" : auth.userID.base64urlString)
                ]
            ]
        ]

        return try await postJson(path: "/passkey/verify-login", body: payload)
    }

    // MARK: - Internals
    private func assertConfigured() throws {
        guard isConfigured else { throw WardenError("Warden no está configurado") }
    }

    private func baseURL(_ path: String) throws -> URL {
        guard let cfg = config else { throw WardenError("Warden no está configurado") }
        let base = cfg.apiBaseUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return URL(string: "\(base)/api\(path)")!
    }

    private func getJson<T: Decodable>(path: String) async throws -> T {
        let req = try makeRequest(path: path, method: "GET", jsonBody: Optional<Data>.none)
        let (data, res) = try await URLSession.shared.data(for: req)
        return try handleResponse(data: data, res: res)
    }

    private func postJson<T: Decodable>(path: String, body: Any) async throws -> T {
        let data = try JSONSerialization.data(withJSONObject: body, options: [])
        let req = try makeRequest(path: path, method: "POST", jsonBody: data)
        let (respData, res) = try await URLSession.shared.data(for: req)
        return try handleResponse(data: respData, res: res)
    }

    private func makeRequest(path: String, method: String, jsonBody: Data?) throws -> URLRequest {
        guard let cfg = config else { throw WardenError("Warden no está configurado") }
        var req = URLRequest(url: try baseURL(path))
        req.httpMethod = method
        req.setValue(cfg.apiKey, forHTTPHeaderField: "x-api-key")

        // 👉 Enviamos también el origin por header (además de la query)
        req.setValue(cfg.rpOrigin, forHTTPHeaderField: "x-client-origin")

        if let body = jsonBody {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return req
    }

    private func handleResponse<T: Decodable>(data: Data, res: URLResponse) throws -> T {
        guard let http = res as? HTTPURLResponse else {
            throw WardenError("Respuesta HTTP inválida")
        }
        guard (200..<300).contains(http.statusCode) else {
            let msg = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["message"] as? String
            throw WardenError(msg ?? "HTTP \(http.statusCode)", status: http.statusCode)
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    // MARK: - ASAuthorization (async)
    private func performAuthorization(requests: [ASAuthorizationRequest], anchor: ASPresentationAnchor) async throws -> ASAuthorization {
        let controller = ASAuthorizationController(authorizationRequests: requests)
        let delegate = AuthorizationDelegate()
        controller.delegate = delegate
        controller.presentationContextProvider = delegate
        delegate.anchor = anchor
        controller.performRequests()
        return try await delegate.result()
    }

    // MARK: - Helpers
    private func encodedRpOriginQueryParam() throws -> String {
        guard let origin = config?.rpOrigin, !origin.isEmpty else {
            throw WardenError("rpOrigin no configurado")
        }
        guard URL(string: origin) != nil else {
            throw WardenError("rpOrigin inválido: \(origin)")
        }
        return origin.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? origin
    }
}

// MARK: - Authorization Delegate (async bridge)
private final class AuthorizationDelegate: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    var anchor: ASPresentationAnchor!
    private var continuation: CheckedContinuation<ASAuthorization, Error>?

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        anchor
    }

    func result() async throws -> ASAuthorization {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<ASAuthorization, Error>) in
            self.continuation = cont
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        continuation?.resume(returning: authorization)
        continuation = nil
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

// MARK: - Minimal models para parsear options del backend (SimpleWebAuthn-like)
private struct PublicKeyCredentialCreationOptions: Decodable {
    struct RP: Decodable { let id: String; let name: String? }
    struct User: Decodable { let id: String; let name: String; let displayName: String? }
    let rp: RP
    let user: User
    let challenge: String // base64url
}

private struct PublicKeyCredentialRequestOptions: Decodable {
    struct RP: Decodable { let id: String }
    struct Allow: Decodable { let id: String; let type: String? }
    let challenge: String // base64url
    let rpId: String?
    let rp: RP?
    let allowCredentials: [Allow]?
}

// MARK: - Base64URL helpers
extension Data {
    init(base64url: String) throws {
        var s = base64url.replacingOccurrences(of: "-", with: "+")
                         .replacingOccurrences(of: "_", with: "/")
        let pad = (4 - s.count % 4) % 4
        if pad > 0 { s.append(String(repeating: "=", count: pad)) }
        guard let d = Data(base64Encoded: s) else { throw WardenError("base64url inválido") }
        self = d
    }
    var base64urlString: String {
        self.base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}

private extension Array where Element == UInt8 {
    func base64urlString() -> String { Data(self).base64urlString }
}

private extension Data {
    /// Para credentialID/userID que son Data → base64url
    var bytes: [UInt8] { [UInt8](self) }
}
