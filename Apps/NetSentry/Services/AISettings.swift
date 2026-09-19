import Foundation
import Observation

/// User-configured connection to an LLM provider for the "Ask AI" assistant.
/// Non-secret fields live in UserDefaults; the API key lives in the Keychain (see `Keychain`).
@MainActor
@Observable
final class AISettings {
    enum Provider: String, CaseIterable, Identifiable, Codable, Sendable {
        case openAI
        case anthropic
        var id: String { rawValue }
        var label: String {
            switch self { case .openAI: "OpenAI-compatible"; case .anthropic: "Anthropic-compatible" }
        }
        var defaultBaseURL: String {
            switch self { case .openAI: "https://api.openai.com/v1"; case .anthropic: "https://api.anthropic.com/v1" }
        }
        var defaultModel: String {
            switch self { case .openAI: "gpt-4o"; case .anthropic: "claude-3-5-sonnet-latest" }
        }
    }

    var provider: Provider
    var baseURL: String
    var model: String
    var temperature: Double
    /// Held in memory for the running session; loaded from and written to the Keychain, never UserDefaults.
    var apiKey: String

    private enum Key {
        static let provider = "ai.provider"
        static let baseURL = "ai.baseURL"
        static let model = "ai.model"
        static let temperature = "ai.temperature"
        static let keychainAccount = "ai.apiKey"
    }

    init() {
        let d = UserDefaults.standard
        let p = Provider(rawValue: d.string(forKey: Key.provider) ?? "") ?? .openAI
        provider = p
        baseURL = d.string(forKey: Key.baseURL) ?? p.defaultBaseURL
        model = d.string(forKey: Key.model) ?? p.defaultModel
        temperature = d.object(forKey: Key.temperature) as? Double ?? 0.2
        apiKey = Keychain.get(account: Key.keychainAccount) ?? ""
    }

    /// True when there is enough to attempt a request.
    var isConfigured: Bool {
        !apiKey.isEmpty && !model.trimmingCharacters(in: .whitespaces).isEmpty && normalizedBaseURL != nil
    }

    /// Base URL trimmed of a trailing slash, validated as an absolute http(s) URL.
    var normalizedBaseURL: URL? {
        var s = baseURL.trimmingCharacters(in: .whitespaces)
        while s.hasSuffix("/") { s.removeLast() }
        guard let url = URL(string: s), let scheme = url.scheme, scheme == "http" || scheme == "https" else { return nil }
        return url
    }

    /// Persists non-secret fields to UserDefaults and the key to the Keychain.
    func save() {
        let d = UserDefaults.standard
        d.set(provider.rawValue, forKey: Key.provider)
        d.set(baseURL, forKey: Key.baseURL)
        d.set(model, forKey: Key.model)
        d.set(temperature, forKey: Key.temperature)
        let key = apiKey.trimmingCharacters(in: .whitespaces)
        if key.isEmpty { Keychain.delete(account: Key.keychainAccount) }
        else { Keychain.set(key, account: Key.keychainAccount) }
    }

    /// Resets base URL and model to the selected provider's defaults (used when switching provider).
    func applyProviderDefaults() {
        baseURL = provider.defaultBaseURL
        model = provider.defaultModel
    }
}
