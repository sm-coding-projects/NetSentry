import AppKit
import SwiftUI
import NetSentryCore
import NetSentryCorrelation
import NetSentryDetection
import NetSentryExport
import UniformTypeIdentifiers

/// Save-panel driven exports. Every export goes through a `RedactionPolicy` chosen in `ExportSheet`.
@MainActor
enum ExportService {
    static func save(data: Data, suggestedName: String, type: UTType) -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.allowedContentTypes = [type]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        do {
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            NSWorkspace.shared.activateFileViewerSelecting([url])
            return url
        } catch {
            NSAlert(error: error).runModal()
            return nil
        }
    }
    static var markdown: UTType { UTType(filenameExtension: "md") ?? .plainText }
}

/// Redaction choices, remembered per app. Presented before every export.
struct ExportSheet: View {
    enum Format: String, CaseIterable, Identifiable { case csv = "CSV", json = "JSON"; var id: String { rawValue } }
    let title: String
    let formats: [Format]
    let onExport: (Format, RedactionPolicy) -> Void
    @Environment(\.dismiss) private var dismiss
    @AppStorage("export.hashInternal") private var hashInternal = false
    @AppStorage("export.hashExternal") private var hashExternal = false
    @AppStorage("export.dropMACs") private var dropMACs = true
    @AppStorage("export.dropHostnames") private var dropHostnames = false
    @AppStorage("export.dropRaw") private var dropRaw = true
    @AppStorage("export.dropNotes") private var dropNotes = false
    @AppStorage("export.dropUsernames") private var dropUsernames = false
    @State private var format: Format

    init(title: String, formats: [Format] = Format.allCases, onExport: @escaping (Format, RedactionPolicy) -> Void) {
        self.title = title; self.formats = formats; self.onExport = onExport; _format = State(initialValue: formats.first ?? .json)
    }

    var policy: RedactionPolicy { RedactionPolicy(hashInternalAddresses: hashInternal, hashExternalAddresses: hashExternal, dropMACs: dropMACs, dropHostnames: dropHostnames, dropRawMessages: dropRaw, dropNotes: dropNotes, dropUsernames: dropUsernames) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.headline)
            if formats.count > 1 { Picker("Format", selection: $format) { ForEach(formats) { Text($0.rawValue).tag($0) } }.pickerStyle(.segmented) }
            GroupBox("Redaction") {
                VStack(alignment: .leading, spacing: 6) {
                    Toggle("Hash internal addresses (keyed per export; the same address stays comparable within the file)", isOn: $hashInternal)
                    Toggle("Hash external addresses", isOn: $hashExternal)
                    Toggle("Remove MAC addresses", isOn: $dropMACs)
                    Toggle("Remove hostnames", isOn: $dropHostnames)
                    Toggle("Remove raw syslog text", isOn: $dropRaw)
                    Toggle("Remove usernames", isOn: $dropUsernames)
                    Toggle("Remove analyst notes", isOn: $dropNotes)
                    HStack { Button("Nothing") { set(.none) }; Button("For sharing") { set(.sharing) }; Spacer(); Text(policy.summary).font(.caption).foregroundStyle(.secondary) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            Text("Exports are written with owner-only permissions. Redaction is irreversible in the file; the store is untouched.").font(.caption).foregroundStyle(.secondary)
            HStack { Spacer(); Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction); Button("Export…") { dismiss(); onExport(format, policy) }.keyboardShortcut(.defaultAction) }
        }
        .padding(16).frame(width: 560)
    }
    private func set(_ p: RedactionPolicy) { hashInternal = p.hashInternalAddresses; hashExternal = p.hashExternalAddresses; dropMACs = p.dropMACs; dropHostnames = p.dropHostnames; dropRaw = p.dropRawMessages; dropNotes = p.dropNotes; dropUsernames = p.dropUsernames }
}

extension AppModel {
    /// Internal-address test used by exports: private ranges plus the configured internal networks.
    nonisolated func isInternalAddress(_ ip: IPAddress, prefixes: [IPPrefix]) -> Bool { ip.isPrivate || ip.isLinkLocal || prefixes.contains { $0.contains(ip) } }
}
