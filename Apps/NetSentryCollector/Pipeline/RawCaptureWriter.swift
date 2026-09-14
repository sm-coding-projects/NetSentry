import Foundation
import NetSentryCore
import os

/// Appends raw datagrams to bounded `.nsraw` files under `<Store>/captures/` when diagnostic capture is on.
actor RawCaptureWriter {
    private let log = Log.logger("capture", process: "collector")
    private let directory: URL
    private var config: DiagnosticCaptureConfiguration
    private var handles: [ListenerKind: FileHandle] = [:]
    private var bytesWritten: Int64 = 0
    private var datagramsWritten = 0
    private var stoppedForLimit = false

    init(storeRoot: URL, config: DiagnosticCaptureConfiguration) {
        directory = storeRoot.appending(path: "captures", directoryHint: .isDirectory)
        self.config = config
    }

    func update(_ c: DiagnosticCaptureConfiguration) {
        config = c
        if !c.enabled { closeAll() }
    }

    var isEnabled: Bool { config.enabled && !stoppedForLimit }

    func write(_ d: RawDatagram) {
        guard config.enabled, !stoppedForLimit else { return }
        if datagramsWritten >= config.maxDatagrams || bytesWritten >= config.maxBytes {
            stoppedForLimit = true
            log.notice("Diagnostic capture reached its limit (\(self.datagramsWritten) datagrams, \(self.bytesWritten) bytes)")
            closeAll()
            return
        }
        let record = RawCaptureFormat.encode(d)
        do {
            let h = try handle(for: d.kind)
            try h.write(contentsOf: record)
            bytesWritten += Int64(record.count)
            datagramsWritten += 1
        } catch {
            log.error("Capture write failed: \(error.localizedDescription, privacy: .public)")
            config.enabled = false
        }
    }

    private func handle(for kind: ListenerKind) throws -> FileHandle {
        if let h = handles[kind] { return h }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let url = directory.appending(path: "\(kind.rawValue)-\(Timestamp.now.seconds).nsraw")
        FileManager.default.createFile(atPath: url.path, contents: RawCaptureFormat.magic, attributes: [.posixPermissions: 0o600])
        let h = try FileHandle(forWritingTo: url)
        try h.seekToEnd()
        handles[kind] = h
        log.notice("Diagnostic capture started: \(url.lastPathComponent, privacy: .public)")
        return h
    }

    func closeAll() {
        for (_, h) in handles { try? h.close() }
        handles.removeAll()
    }
}
