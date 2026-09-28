import SwiftUI

/// Right-hand inspector of a table screen. Screens show it only while a row is selected; the close button
/// (or Escape in the table) clears the selection, which collapses it again.
struct DetailPane<Content: View>: View {
    let onClose: () -> Void
    @ViewBuilder let content: Content

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Button(action: onClose) { Image(systemName: "xmark") }
                    .buttonStyle(.borderless)
                    .help("Close details")
                    .accessibilityLabel("Close details")
            }
            .padding(.horizontal, 10).padding(.top, 6)
            content.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }
}
