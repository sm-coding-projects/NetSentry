import AppKit
import SwiftUI

/// App-wide text size, changed with ⌘+ / ⌘− / ⌘0 and persisted in user defaults.
/// macOS ignores Dynamic Type, so every font in the app is sized from the system's point size for its
/// text style multiplied by this factor (see `scaledFont`). The window roots also set a scaled body font,
/// which plain `Text`, tables, lists and controls inherit.
enum TextScale {
    static let defaultsKey = "textScale"
    static let steps: [Double] = [0.85, 1.0, 1.15, 1.3, 1.5, 1.75, 2.0]

    static func larger(than s: Double) -> Double { steps.first { $0 > s + 0.001 } ?? steps[steps.count - 1] }
    static func smaller(than s: Double) -> Double { steps.last { $0 < s - 0.001 } ?? steps[0] }
    static func canGrow(_ s: Double) -> Bool { s < steps[steps.count - 1] - 0.001 }
    static func canShrink(_ s: Double) -> Bool { s > steps[0] + 0.001 }
}

extension EnvironmentValues {
    @Entry var textScale: Double = 1
}

extension Font {
    /// The system font for `style` (size and weight as macOS defines them) scaled by `scale`.
    static func scaled(_ style: TextStyle, scale: Double, design: Design = .default) -> Font {
        let base = NSFont.preferredFont(forTextStyle: style.nsTextStyle)
        let weight: Weight = base.fontDescriptor.symbolicTraits.contains(.bold) ? .bold : .regular
        return .system(size: (base.pointSize * scale).rounded(), weight: weight, design: design)
    }
}

extension Font.TextStyle {
    fileprivate var nsTextStyle: NSFont.TextStyle {
        switch self {
        case .largeTitle: .largeTitle
        case .title: .title1
        case .title2: .title2
        case .title3: .title3
        case .headline: .headline
        case .subheadline: .subheadline
        case .callout: .callout
        case .footnote: .footnote
        case .caption: .caption1
        case .caption2: .caption2
        default: .body
        }
    }
}

private struct ScaledFont: ViewModifier {
    @Environment(\.textScale) private var scale
    let style: Font.TextStyle
    let design: Font.Design
    let transform: (Font) -> Font

    func body(content: Content) -> some View {
        content.font(transform(.scaled(style, scale: scale, design: design)))
    }
}

extension View {
    /// Text-style font that follows the app-wide text size. `transform` adds traits, e.g. `{ $0.bold() }`.
    func scaledFont(_ style: Font.TextStyle, design: Font.Design = .default, _ transform: @escaping (Font) -> Font = { $0 }) -> some View {
        modifier(ScaledFont(style: style, design: design, transform: transform))
    }

    /// Root of a window: publishes the text size and sets the scaled body font everything else inherits.
    func appTextScale(_ scale: Double) -> some View {
        environment(\.textScale, scale).font(.scaled(.body, scale: scale))
    }
}

/// View-menu items for the app-wide text size.
struct TextSizeCommands: Commands {
    @AppStorage(TextScale.defaultsKey) private var scale = 1.0

    var body: some Commands {
        CommandGroup(after: .toolbar) {
            Button("Increase Text Size") { scale = TextScale.larger(than: scale) }
                .keyboardShortcut("+", modifiers: .command)
                .disabled(!TextScale.canGrow(scale))
            Button("Decrease Text Size") { scale = TextScale.smaller(than: scale) }
                .keyboardShortcut("-", modifiers: .command)
                .disabled(!TextScale.canShrink(scale))
            Button("Actual Size") { scale = 1.0 }
                .keyboardShortcut("0", modifiers: .command)
                .disabled(scale == 1.0)
            Divider()
        }
    }
}
