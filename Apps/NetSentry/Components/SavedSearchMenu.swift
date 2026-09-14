import SwiftUI
import NetSentryAnalytics

/// Menu listing the saved searches for a view; selecting one applies its filter.
struct SavedSearchMenu: View {
    @Environment(AppModel.self) private var model
    let view: String
    let apply: (RecordFilter) -> Void
    @State private var items: [(id: Int64, name: String, query: RecordFilter)] = []

    var body: some View {
        Menu("Saved") {
            if items.isEmpty { Text("No saved searches").disabled(true) }
            ForEach(items, id: \.id) { item in Button(item.name) { apply(item.query) } }
        }
        .frame(width: 90)
        .onAppear { items = model.savedSearches(view: view) }
        .accessibilityLabel("Saved searches")
    }
}
