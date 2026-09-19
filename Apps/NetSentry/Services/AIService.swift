import Foundation
import NetSentryCore
import Observation

/// Drives the "Ask AI" conversation: builds the system prompt, streams from the configured provider
/// (OpenAI- or Anthropic-compatible), runs any tools the model asks for against live telemetry, and
/// loops until the model produces a final answer. Responses stream token-by-token; reasoning-model
/// `<think>` content is separated out so the UI can show it collapsed.
@MainActor
@Observable
final class AIService {
    let settings: AISettings
    private let runner: AIToolRunner
    private weak var model: AppModel?

    /// Full transcript sent to the provider every turn (system + user + assistant + tool messages).
    private(set) var transcript: [AIMessage] = []
    var isResponding = false
    /// Human-readable status shown while a turn runs, e.g. "Running query_flows…". Nil once text streams.
    var activity: String?
    var lastError: String?
    /// Bumped on every streamed delta so the view can auto-scroll as text arrives.
    private(set) var streamTick = 0

    private let maxToolIterations = 6
    private let session: URLSession = {
        let c = URLSessionConfiguration.default
        c.timeoutIntervalForRequest = 180
        c.waitsForConnectivity = false
        return URLSession(configuration: c)
    }()

    init(settings: AISettings, model: AppModel, analytics: AnalyticsService) {
        self.settings = settings
        self.model = model
        self.runner = AIToolRunner(model: model, analytics: analytics)
    }

    /// The user-visible turns: user messages, plus assistant messages that carry text or reasoning.
    var visibleMessages: [AIMessage] {
        transcript.filter { m in
            m.role == .user || (m.role == .assistant && (m.text?.isEmpty == false || m.reasoning?.isEmpty == false))
        }
    }

    func reset() {
        transcript.removeAll()
        lastError = nil
        activity = nil
    }

    // MARK: - Conversation

    func send(_ userText: String) async {
        let text = userText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !isResponding else { return }
        guard settings.isConfigured, let baseURL = settings.normalizedBaseURL else {
            transcript.append(.user(text))
            appendError(AIError.notConfigured)
            return
        }

        if transcript.first?.role == .system { transcript.removeFirst() }
        transcript.insert(.system(systemPrompt()), at: 0)
        transcript.append(.user(text))

        isResponding = true
        lastError = nil
        defer { isResponding = false; activity = nil }

        do {
            var iterations = 0
            while iterations < maxToolIterations {
                iterations += 1
                activity = "Thinking…"

                // Placeholder the stream fills in place.
                transcript.append(AIMessage(role: .assistant, streaming: true))
                let idx = transcript.count - 1
                try await streamTurn(baseURL: baseURL, into: idx)
                transcript[idx].streaming = false

                let assistant = transcript[idx]
                guard !assistant.toolCalls.isEmpty else { return }

                for call in assistant.toolCalls {
                    activity = "Running \(friendlyToolName(call.name))…"
                    let result = await runner.run(name: call.name, argumentsJSON: call.argumentsJSON)
                    transcript.append(.toolResult(id: call.id, name: call.name, content: result))
                }
            }
            transcript.append(AIMessage(role: .assistant, text: "I gathered a lot of data but didn't finish forming an answer. Try narrowing the question."))
        } catch {
            appendError(error)
        }
    }

    private func appendError(_ error: Error) {
        let message = (error as? AIError)?.errorDescription ?? error.localizedDescription
        lastError = message
        // Reuse a trailing empty streaming placeholder if present.
        if let last = transcript.indices.last, transcript[last].role == .assistant,
           transcript[last].text?.isEmpty != false, transcript[last].reasoning?.isEmpty != false {
            transcript[last].text = "⚠️ \(message)"
            transcript[last].streaming = false
        } else {
            transcript.append(AIMessage(role: .assistant, text: "⚠️ \(message)"))
        }
    }

    private func friendlyToolName(_ name: String) -> String {
        switch name {
        case "get_network_overview": "network overview"
        case "query_flows": "flow lookup"
        case "top_talkers": "top talkers"
        case "list_clients": "client list"
        case "list_alerts": "security alerts"
        case "bandwidth_time_series": "bandwidth trend"
        default: name
        }
    }

    /// Applies streamed raw text to a transcript message, splitting out `<think>` reasoning.
    private func applyStreamedText(_ raw: String, to idx: Int) {
        let (reasoning, answer) = Self.splitThinking(raw)
        transcript[idx].reasoning = reasoning.isEmpty ? nil : reasoning
        transcript[idx].text = answer.isEmpty ? nil : answer
        if !raw.isEmpty { activity = nil }
        streamTick &+= 1
    }

    /// Separates `<think>…</think>` spans (reasoning) from the rest (answer). Handles an unclosed
    /// trailing `<think>` while streaming.
    static func splitThinking(_ s: String) -> (reasoning: String, answer: String) {
        guard s.contains("<think>") else { return ("", s) }
        var reasoning = "", answer = ""
        var rest = Substring(s)
        while let open = rest.range(of: "<think>") {
            answer += rest[..<open.lowerBound]
            let after = rest[open.upperBound...]
            if let close = after.range(of: "</think>") {
                reasoning += after[..<close.lowerBound]
                rest = after[close.upperBound...]
            } else {
                reasoning += after
                rest = ""
                break
            }
        }
        answer += rest
        return (reasoning.trimmingCharacters(in: .whitespacesAndNewlines),
                answer.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    // MARK: - System prompt

    private func systemPrompt() -> String {
        let connected = model?.connectionState == .connected
        let demo = model?.health?.demoWorkspace ?? model?.configuration.demoWorkspace ?? false
        let now = Date().formatted(date: .abbreviated, time: .standard)
        return """
        You are the assistant embedded in \(Branding.productName), a local-only macOS app that observes a home/small-office network by collecting NetFlow/IPFIX flow records and syslog events (typically from a UniFi gateway) and running a local detection engine.

        Your job is to help the user understand and troubleshoot their network. Base every factual claim on data you retrieve with the provided tools — never invent hosts, IPs, byte counts, or alerts. If the tools return nothing for a window, say so plainly and suggest widening the time range.

        How to work:
        - For broad questions ("how's my network", "anything wrong"), start with get_network_overview and list_alerts.
        - To investigate a specific device or connection, resolve it with list_clients if needed, then use query_flows (by ip / client_id / dst_port) and top_talkers.
        - Bytes are raw octets; prefer the *_human fields when quoting sizes to the user. "direction" is from the local network's perspective: outbound = a local host initiating out, inbound = external reaching in, lan = internal-to-internal.

        Formatting your answer (render as GitHub-flavored Markdown):
        - Open with a one-line bottom-line summary in **bold**.
        - Use short `##` section headings only when the answer has multiple parts.
        - Prefer tight bullet lists (`- `) over long paragraphs. Put IPs, ports, and hostnames in `code`.
        - Keep it concise. Note when something looks normal, not only when it looks wrong. Do not restate the raw tool JSON.

        Context: current time is \(now). Collector is \(connected ? "connected" : "NOT connected").\(demo ? " This is a DEMO workspace with SIMULATED data — say so if the user might mistake it for their real network." : "")
        """
    }

    // MARK: - Streaming dispatch

    private func streamTurn(baseURL: URL, into idx: Int) async throws {
        switch settings.provider {
        case .openAI: try await streamOpenAI(baseURL: baseURL, into: idx)
        case .anthropic: try await streamAnthropic(baseURL: baseURL, into: idx)
        }
    }

    private func postJSON(url: URL, body: [String: Any], headers: [String: String]) throws -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        return req
    }

    /// Opens an SSE stream. Throws `AIError.badResponse` for non-2xx, reading the error body first.
    private func openStream(_ request: URLRequest) async throws -> (URLSession.AsyncBytes, HTTPURLResponse) {
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse else { throw AIError.transport("No HTTP response") }
            if !(200..<300).contains(http.statusCode) {
                var body = ""
                for try await line in bytes.lines { body += line + "\n"; if body.count > 2000 { break } }
                throw AIError.badResponse(status: http.statusCode, body: body)
            }
            return (bytes, http)
        } catch let e as AIError {
            throw e
        } catch {
            throw AIError.transport(error.localizedDescription)
        }
    }

    // MARK: OpenAI streaming

    private func streamOpenAI(baseURL: URL, into idx: Int) async throws {
        let body: [String: Any] = [
            "model": settings.model,
            "messages": openAIMessages(),
            "tools": AIToolRunner.tools.map(\.openAIJSON),
            "tool_choice": "auto",
            "temperature": settings.temperature,
            "stream": true,
        ]
        let req = try postJSON(url: baseURL.appending(path: "chat/completions"), body: body,
                               headers: ["Authorization": "Bearer \(settings.apiKey)"])
        let (bytes, _) = try await openStream(req)

        var raw = ""
        var toolAcc: [Int: (id: String, name: String, args: String)] = [:]
        do {
            for try await line in bytes.lines {
                guard line.hasPrefix("data:") else { continue }
                let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                if payload == "[DONE]" { break }
                guard let obj = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any],
                      let choices = obj["choices"] as? [[String: Any]], let choice = choices.first else { continue }
                guard let delta = choice["delta"] as? [String: Any] else { continue }
                if let content = delta["content"] as? String, !content.isEmpty {
                    raw += content
                    applyStreamedText(raw, to: idx)
                }
                // Some OpenAI-compatible servers expose reasoning separately.
                if let r = (delta["reasoning_content"] ?? delta["reasoning"]) as? String, !r.isEmpty {
                    transcript[idx].reasoning = (transcript[idx].reasoning ?? "") + r
                    streamTick &+= 1
                }
                if let calls = delta["tool_calls"] as? [[String: Any]] {
                    for c in calls {
                        let index = c["index"] as? Int ?? 0
                        var acc = toolAcc[index] ?? ("", "", "")
                        if let id = c["id"] as? String { acc.id = id }
                        if let fn = c["function"] as? [String: Any] {
                            if let n = fn["name"] as? String { acc.name = n }
                            if let a = fn["arguments"] as? String { acc.args += a }
                        }
                        toolAcc[index] = acc
                    }
                }
            }
        } catch { throw AIError.transport(error.localizedDescription) }

        transcript[idx].toolCalls = toolAcc.sorted { $0.key < $1.key }.compactMap { _, v in
            v.name.isEmpty ? nil : AIToolCall(id: v.id.isEmpty ? UUID().uuidString : v.id, name: v.name, argumentsJSON: v.args.isEmpty ? "{}" : v.args)
        }
    }

    private func openAIMessages() -> [[String: Any]] {
        var messages: [[String: Any]] = []
        for m in transcript where !(m.role == .assistant && m.streaming) {
            switch m.role {
            case .system: messages.append(["role": "system", "content": m.text ?? ""])
            case .user: messages.append(["role": "user", "content": m.text ?? ""])
            case .assistant:
                var msg: [String: Any] = ["role": "assistant", "content": m.text ?? ""]
                if !m.toolCalls.isEmpty {
                    msg["tool_calls"] = m.toolCalls.map { c in
                        ["id": c.id, "type": "function", "function": ["name": c.name, "arguments": c.argumentsJSON]]
                    }
                }
                messages.append(msg)
            case .tool:
                messages.append(["role": "tool", "tool_call_id": m.toolCallID ?? "", "content": m.text ?? ""])
            }
        }
        return messages
    }

    // MARK: Anthropic streaming

    private func streamAnthropic(baseURL: URL, into idx: Int) async throws {
        let (system, messages) = anthropicMessages()
        var body: [String: Any] = [
            "model": settings.model,
            "max_tokens": 2048,
            "messages": messages,
            "tools": AIToolRunner.tools.map(\.anthropicJSON),
            "temperature": settings.temperature,
            "stream": true,
        ]
        if !system.isEmpty { body["system"] = system }
        let req = try postJSON(url: baseURL.appending(path: "messages"), body: body,
                               headers: ["x-api-key": settings.apiKey, "anthropic-version": "2023-06-01"])
        let (bytes, _) = try await openStream(req)

        var raw = ""
        var blockTypes: [Int: String] = [:]
        var toolAcc: [Int: (id: String, name: String, args: String)] = [:]
        do {
            for try await line in bytes.lines {
                guard line.hasPrefix("data:") else { continue }
                let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                guard !payload.isEmpty,
                      let obj = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any] else { continue }
                switch obj["type"] as? String {
                case "content_block_start":
                    let index = obj["index"] as? Int ?? 0
                    if let block = obj["content_block"] as? [String: Any] {
                        blockTypes[index] = block["type"] as? String
                        if block["type"] as? String == "tool_use" {
                            toolAcc[index] = (block["id"] as? String ?? "", block["name"] as? String ?? "", "")
                        }
                    }
                case "content_block_delta":
                    let index = obj["index"] as? Int ?? 0
                    guard let delta = obj["delta"] as? [String: Any] else { break }
                    switch delta["type"] as? String {
                    case "text_delta":
                        if let t = delta["text"] as? String { raw += t; applyStreamedText(raw, to: idx) }
                    case "thinking_delta":
                        if let t = delta["thinking"] as? String {
                            transcript[idx].reasoning = (transcript[idx].reasoning ?? "") + t; streamTick &+= 1
                        }
                    case "input_json_delta":
                        if let pj = delta["partial_json"] as? String, var acc = toolAcc[index] { acc.args += pj; toolAcc[index] = acc }
                    default: break
                    }
                case "message_stop": break
                default: break
                }
            }
        } catch { throw AIError.transport(error.localizedDescription) }

        transcript[idx].toolCalls = toolAcc.sorted { $0.key < $1.key }.compactMap { _, v in
            v.name.isEmpty ? nil : AIToolCall(id: v.id, name: v.name, argumentsJSON: v.args.isEmpty ? "{}" : v.args)
        }
    }

    private func anthropicMessages() -> (system: String, messages: [[String: Any]]) {
        var system = ""
        var messages: [[String: Any]] = []
        var pending: [[String: Any]] = []
        func flush() { if !pending.isEmpty { messages.append(["role": "user", "content": pending]); pending = [] } }

        for m in transcript where !(m.role == .assistant && m.streaming) {
            switch m.role {
            case .system: system = m.text ?? ""
            case .user:
                flush()
                messages.append(["role": "user", "content": [["type": "text", "text": m.text ?? ""]]])
            case .assistant:
                flush()
                var blocks: [[String: Any]] = []
                if let t = m.text, !t.isEmpty { blocks.append(["type": "text", "text": t]) }
                for c in m.toolCalls {
                    let input = (try? JSONSerialization.jsonObject(with: Data(c.argumentsJSON.utf8))) as? [String: Any] ?? [:]
                    blocks.append(["type": "tool_use", "id": c.id, "name": c.name, "input": input])
                }
                if blocks.isEmpty { blocks.append(["type": "text", "text": ""]) }
                messages.append(["role": "assistant", "content": blocks])
            case .tool:
                pending.append(["type": "tool_result", "tool_use_id": m.toolCallID ?? "", "content": m.text ?? ""])
            }
        }
        flush()
        return (system, messages)
    }

    // MARK: - Model listing

    /// Fetches the provider's available model ids via `GET {baseURL}/models`.
    func fetchModels() async throws -> [String] {
        guard !settings.apiKey.isEmpty, let baseURL = settings.normalizedBaseURL else { throw AIError.notConfigured }
        var req = URLRequest(url: baseURL.appending(path: "models"))
        req.httpMethod = "GET"
        switch settings.provider {
        case .openAI:
            req.setValue("Bearer \(settings.apiKey)", forHTTPHeaderField: "Authorization")
        case .anthropic:
            req.setValue(settings.apiKey, forHTTPHeaderField: "x-api-key")
            req.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")
        }
        let data: Data
        do {
            let (d, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse else { throw AIError.transport("No HTTP response") }
            guard (200..<300).contains(http.statusCode) else {
                throw AIError.badResponse(status: http.statusCode, body: String(data: d, encoding: .utf8) ?? "")
            }
            data = d
        } catch let e as AIError { throw e }
        catch { throw AIError.transport(error.localizedDescription) }

        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let arr = root["data"] as? [[String: Any]] else { throw AIError.decoding("missing model list") }
        return arr.compactMap { $0["id"] as? String }.sorted()
    }
}
