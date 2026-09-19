import SwiftUI

/// Lightweight GitHub-flavored-Markdown renderer for assistant answers. Full `AttributedString`
/// markdown collapses block structure (headings, lists, code fences) into one inline run; this
/// parses the text into block elements and renders each, using inline markdown only within a block.
struct FormattedText: View {
    let text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(Self.parse(text).enumerated()), id: \.offset) { _, block in
                view(for: block)
            }
        }
    }

    @ViewBuilder
    private func view(for block: Block) -> some View {
        switch block {
        case .heading(let level, let text):
            Text(inline(text))
                .font(level <= 1 ? .title3.bold() : level == 2 ? .headline : .subheadline.bold())
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 2)
        case .paragraph(let text):
            Text(inline(text))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        case .bullet(let text, let indent):
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("•").foregroundStyle(.secondary)
                Text(inline(text)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            .padding(.leading, CGFloat(indent) * 16)
        case .ordered(let number, let text):
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(number).foregroundStyle(.secondary).monospacedDigit()
                Text(inline(text)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
        case .code(let code):
            Text(code)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
        case .rule:
            Divider().padding(.vertical, 2)
        }
    }

    private func inline(_ s: String) -> AttributedString {
        (try? AttributedString(markdown: s, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)))
            ?? AttributedString(s)
    }

    // MARK: - Block model

    enum Block {
        case heading(level: Int, text: String)
        case paragraph(String)
        case bullet(text: String, indent: Int)
        case ordered(number: String, text: String)
        case code(String)
        case rule
    }

    static func parse(_ text: String) -> [Block] {
        var blocks: [Block] = []
        var paragraph: [String] = []
        var code: [String] = []
        var inCode = false

        func flushParagraph() {
            if !paragraph.isEmpty {
                blocks.append(.paragraph(paragraph.joined(separator: "\n")))
                paragraph = []
            }
        }

        for rawLine in text.components(separatedBy: "\n") {
            let line = rawLine
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.hasPrefix("```") {
                if inCode { blocks.append(.code(code.joined(separator: "\n"))); code = []; inCode = false }
                else { flushParagraph(); inCode = true }
                continue
            }
            if inCode { code.append(line); continue }

            if trimmed.isEmpty { flushParagraph(); continue }

            // Horizontal rule
            if trimmed == "---" || trimmed == "***" || trimmed == "___" {
                flushParagraph(); blocks.append(.rule); continue
            }
            // Heading
            if let h = heading(trimmed) {
                flushParagraph(); blocks.append(.heading(level: h.0, text: h.1)); continue
            }
            // Bullet (-, *, +) with optional leading indentation
            if let b = bullet(line) {
                flushParagraph(); blocks.append(.bullet(text: b.text, indent: b.indent)); continue
            }
            // Ordered list "1. text"
            if let o = ordered(trimmed) {
                flushParagraph(); blocks.append(.ordered(number: o.0, text: o.1)); continue
            }
            paragraph.append(trimmed)
        }
        if inCode, !code.isEmpty { blocks.append(.code(code.joined(separator: "\n"))) }
        flushParagraph()
        return blocks
    }

    private static func heading(_ s: String) -> (Int, String)? {
        guard s.hasPrefix("#") else { return nil }
        var level = 0
        var idx = s.startIndex
        while idx < s.endIndex, s[idx] == "#", level < 6 { level += 1; idx = s.index(after: idx) }
        guard idx < s.endIndex, s[idx] == " " else { return nil }
        return (level, String(s[s.index(after: idx)...]).trimmingCharacters(in: .whitespaces))
    }

    private static func bullet(_ line: String) -> (text: String, indent: Int)? {
        let leading = line.prefix { $0 == " " }.count
        let t = line.trimmingCharacters(in: .whitespaces)
        for marker in ["- ", "* ", "+ ", "• "] where t.hasPrefix(marker) {
            return (String(t.dropFirst(marker.count)), min(leading / 2, 4))
        }
        return nil
    }

    private static func ordered(_ s: String) -> (String, String)? {
        guard let dot = s.firstIndex(of: "."), dot > s.startIndex else { return nil }
        let numPart = s[s.startIndex..<dot]
        guard numPart.allSatisfy(\.isNumber), s.index(after: dot) < s.endIndex, s[s.index(after: dot)] == " " else { return nil }
        let rest = String(s[s.index(dot, offsetBy: 2)...])
        return ("\(numPart).", rest)
    }
}
