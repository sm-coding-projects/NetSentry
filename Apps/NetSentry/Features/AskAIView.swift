import SwiftUI
import NetSentryCore

/// Chat assistant that answers questions about the network by calling tools over live telemetry.
struct AskAIView: View {
    @Environment(AIService.self) private var ai
    @Environment(AppModel.self) private var model
    @State private var input = ""
    @FocusState private var inputFocused: Bool

    private let suggestions = [
        "Is anything wrong with my network right now?",
        "Which devices are using the most bandwidth in the last hour?",
        "Show me the top external destinations today.",
        "Are there any open security alerts?",
    ]

    var body: some View {
        VStack(spacing: 0) {
            if !ai.settings.isConfigured { notConfiguredBanner }
            transcriptScroll
            Divider()
            inputBar
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { ai.reset() } label: { Label("New chat", systemImage: "square.and.pencil") }
                    .disabled(ai.visibleMessages.isEmpty || ai.isResponding)
                    .help("Start a new conversation")
            }
        }
    }

    // MARK: - Banner

    private var notConfiguredBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            Text("Ask AI isn't connected to a provider yet.")
            Button("Open Settings") { model.requestedSection = .settings }
                .buttonStyle(.link)
            Spacer()
        }
        .font(.callout)
        .padding(.horizontal, 16).padding(.vertical, 10)
        .background(.orange.opacity(0.12))
    }

    // MARK: - Transcript

    private var transcriptScroll: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 18) {
                    if ai.visibleMessages.isEmpty { emptyState }
                    ForEach(ai.visibleMessages) { message in
                        MessageBubble(message: message).id(message.id)
                    }
                    if showThinkingRow {
                        ActivityRow(text: ai.activity ?? "Thinking…").id("activity")
                    }
                    Color.clear.frame(height: 1).id("bottom")
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .onChange(of: ai.visibleMessages.count) { _, _ in scrollToBottom(proxy) }
            .onChange(of: ai.streamTick) { _, _ in scrollToBottom(proxy, animated: false) }
            .onChange(of: ai.activity) { _, _ in scrollToBottom(proxy) }
            .onChange(of: ai.isResponding) { _, _ in scrollToBottom(proxy) }
        }
    }

    /// Show the standalone spinner only while waiting — not once text is streaming in.
    private var showThinkingRow: Bool {
        ai.isResponding && ai.activity != nil
    }

    private func scrollToBottom(_ proxy: ScrollViewProxy, animated: Bool = true) {
        let go = { proxy.scrollTo("bottom", anchor: .bottom) }
        if animated { withAnimation(.easeOut(duration: 0.15)) { go() } } else { go() }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Image(systemName: "sparkles").font(.largeTitle).foregroundStyle(.tint)
                Text("Ask about your network").font(.title2.bold())
                Text("I can read the flows and events \(Branding.productName) is collecting and investigate on your behalf. Ask in plain language.")
                    .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .padding(.bottom, 4)
            ForEach(suggestions, id: \.self) { s in
                Button { submit(s) } label: {
                    HStack {
                        Image(systemName: "arrow.up.right").font(.caption).foregroundStyle(.secondary)
                        Text(s)
                        Spacer()
                    }
                    .padding(10)
                    .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
                }
                .buttonStyle(.plain)
                .disabled(!ai.settings.isConfigured)
            }
        }
        .frame(maxWidth: 560, alignment: .leading)
        .padding(.vertical, 12)
    }

    // MARK: - Input

    private var inputBar: some View {
        HStack(alignment: .bottom, spacing: 8) {
            TextField("Ask about your network…", text: $input, axis: .vertical)
                .textFieldStyle(.plain)
                .lineLimit(1...6)
                .padding(10)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
                .focused($inputFocused)
                .onSubmit { submit(input) }
                .disabled(ai.isResponding)
            Button { submit(input) } label: {
                Image(systemName: "arrow.up.circle.fill").font(.title)
            }
            .buttonStyle(.plain)
            .foregroundStyle(canSend ? Color.accentColor : Color.secondary)
            .disabled(!canSend)
            .keyboardShortcut(.return, modifiers: [])
        }
        .padding(12)
        .onAppear { inputFocused = true }
    }

    private var canSend: Bool {
        !ai.isResponding && !input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func submit(_ text: String) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, !ai.isResponding else { return }
        input = ""
        Task { await ai.send(t) }
    }
}

// MARK: - Message bubble

private struct MessageBubble: View {
    let message: AIMessage

    var body: some View {
        if message.role == .user {
            HStack {
                Spacer(minLength: 40)
                Text(message.text ?? "")
                    .textSelection(.enabled)
                    .padding(.horizontal, 12).padding(.vertical, 8)
                    .background(Color.accentColor.opacity(0.9), in: RoundedRectangle(cornerRadius: 12))
                    .foregroundStyle(.white)
            }
        } else {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "sparkles")
                    .foregroundStyle(.tint)
                    .frame(width: 22, height: 22)
                    .background(.quaternary.opacity(0.6), in: Circle())
                VStack(alignment: .leading, spacing: 8) {
                    if let reasoning = message.reasoning, !reasoning.isEmpty {
                        ReasoningDisclosure(text: reasoning, streaming: message.streaming && (message.text?.isEmpty != false))
                    }
                    if let text = message.text, !text.isEmpty {
                        FormattedText(text: text)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Spacer(minLength: 20)
            }
        }
    }
}

/// Collapsible reasoning-model "thinking" content. Collapsed by default; a subtle pill toggles it.
private struct ReasoningDisclosure: View {
    let text: String
    let streaming: Bool
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button { withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() } } label: {
                HStack(spacing: 6) {
                    if streaming {
                        ProgressView().controlSize(.mini)
                        Text("Thinking…")
                    } else {
                        Image(systemName: "brain")
                        Text("Reasoning")
                    }
                    Image(systemName: expanded ? "chevron.down" : "chevron.right").font(.caption2)
                }
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(.quaternary.opacity(0.5), in: Capsule())
            }
            .buttonStyle(.plain)

            if expanded {
                Text(text)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.leading, 10)
                    .overlay(alignment: .leading) { Rectangle().fill(.quaternary).frame(width: 2) }
            }
        }
    }
}

private struct ActivityRow: View {
    let text: String
    var body: some View {
        HStack(spacing: 10) {
            ProgressView().controlSize(.small)
            Text(text).foregroundStyle(.secondary).font(.callout)
        }
        .padding(.leading, 32)
    }
}
