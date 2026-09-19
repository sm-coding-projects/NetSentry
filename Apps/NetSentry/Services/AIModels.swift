import Foundation

/// Provider-neutral chat primitives. `AIService` encodes these into either the OpenAI
/// chat-completions shape or the Anthropic messages shape, so the rest of the app only ever
/// deals with these types.

enum AIRole: String, Sendable, Codable {
    case system, user, assistant, tool
}

/// A request from the model to run one of our tools.
struct AIToolCall: Sendable, Codable, Hashable, Identifiable {
    var id: String            // provider-assigned call id (needed to correlate the result)
    var name: String
    var argumentsJSON: String // raw JSON object string
}

/// One entry in the transcript that is sent to the provider on every turn.
struct AIMessage: Sendable, Codable, Identifiable {
    var id = UUID()
    var role: AIRole
    var text: String?
    /// Reasoning-model "thinking" content, shown collapsed in the UI and never sent back to the provider.
    var reasoning: String?
    /// True while this message is still being streamed in.
    var streaming: Bool = false
    /// Present on assistant turns that requested tools.
    var toolCalls: [AIToolCall] = []
    /// Present on `.tool` turns: which call this answers, and its name (for readability).
    var toolCallID: String?
    var toolName: String?

    static func system(_ text: String) -> AIMessage { AIMessage(role: .system, text: text) }
    static func user(_ text: String) -> AIMessage { AIMessage(role: .user, text: text) }
    static func toolResult(id: String, name: String, content: String) -> AIMessage {
        AIMessage(role: .tool, text: content, toolCallID: id, toolName: name)
    }
}

/// A tool the model can call. `parameters` is a JSON Schema object describing the arguments.
struct AITool {
    var name: String
    var description: String
    var parameters: [String: Any]

    /// OpenAI `tools` entry.
    var openAIJSON: [String: Any] {
        ["type": "function", "function": ["name": name, "description": description, "parameters": parameters]]
    }
    /// Anthropic `tools` entry.
    var anthropicJSON: [String: Any] {
        ["name": name, "description": description, "input_schema": parameters]
    }
}

/// Errors surfaced to the chat UI as an assistant error bubble.
enum AIError: LocalizedError {
    case notConfigured
    case badResponse(status: Int, body: String)
    case decoding(String)
    case transport(String)

    var errorDescription: String? {
        switch self {
        case .notConfigured:
            "Ask AI isn't configured yet. Open Settings → Ask AI and enter a base URL, API key, and model."
        case .badResponse(let status, let body):
            "The provider returned HTTP \(status).\n\(body.prefix(600))"
        case .decoding(let detail):
            "Couldn't understand the provider's response: \(detail)"
        case .transport(let detail):
            "Network error: \(detail)"
        }
    }
}
