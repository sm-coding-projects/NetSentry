import Foundation

/// Storage budget limits (bytes).
public enum StorageBudget {
    public static let minimum: Int64 = 5 * 1_000_000_000
    public static let maximum: Int64 = 500 * 1_000_000_000
    public static let presetsGB: [Int64] = [5, 10, 25, 50, 100, 250, 500]
    public static func clamp(_ bytes: Int64) -> Int64 { min(max(bytes, minimum), maximum) }
}

/// Fractions of the budget assigned to each category. Must sum to 1.0 (validated on apply).
public struct BudgetAllocation: Codable, Sendable, Hashable {
    public var flows: Double = 0.55
    public var events: Double = 0.20
    public var raw: Double = 0.10
    public var metadata: Double = 0.10
    public var reserve: Double = 0.05
    public init() {}
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        flows = try c.decodeIfPresent(Double.self, forKey: .flows) ?? flows
        events = try c.decodeIfPresent(Double.self, forKey: .events) ?? events
        raw = try c.decodeIfPresent(Double.self, forKey: .raw) ?? raw
        metadata = try c.decodeIfPresent(Double.self, forKey: .metadata) ?? metadata
        reserve = try c.decodeIfPresent(Double.self, forKey: .reserve) ?? reserve
    }
    public var sum: Double { flows + events + raw + metadata + reserve }
    public var isValid: Bool { abs(sum - 1.0) < 0.001 && [flows, events, raw, metadata, reserve].allSatisfy { $0 >= 0.01 } }
}

public struct SafetyThreshold: Codable, Sendable, Hashable {
    public enum Mode: String, Codable, Sendable { case automatic, fixed }
    public var mode: Mode = .automatic
    public var fixedBytes: Int64 = 10 * 1_000_000_000
    public init() {}
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode = try c.decodeIfPresent(Mode.self, forKey: .mode) ?? mode
        fixedBytes = try c.decodeIfPresent(Int64.self, forKey: .fixedBytes) ?? fixedBytes
    }
    /// Greater of 10 GB or 5 % of the volume, unless fixed.
    public func bytes(forVolumeSize volume: Int64) -> Int64 {
        switch mode {
        case .fixed: fixedBytes
        case .automatic: max(10 * 1_000_000_000, volume / 20)
        }
    }
}

public struct ListenerConfiguration: Codable, Sendable, Hashable, Identifiable {
    public var id: String { "\(kind.rawValue)-\(transport.rawValue)-\(port)" }
    public var kind: ListenerKind
    public var transport: Transport
    public var port: UInt16
    /// BSD interface name (e.g. "en0") or nil for all interfaces.
    public var interface: String?
    public var enabled: Bool
    public init(kind: ListenerKind, transport: Transport, port: UInt16, interface: String? = nil, enabled: Bool = true) {
        self.kind = kind; self.transport = transport; self.port = port; self.interface = interface; self.enabled = enabled
    }
    public static let defaults: [ListenerConfiguration] = [
        .init(kind: .ipfix, transport: .udp, port: 4739),
        .init(kind: .ipfix, transport: .udp, port: 2055),   // UniFi's NetFlow default
        .init(kind: .syslog, transport: .udp, port: 5514),
        .init(kind: .syslog, transport: .tcp, port: 5514, enabled: false),
    ]
}

public struct GeoIPConfiguration: Codable, Sendable, Hashable {
    public var cityDatabasePath: String?
    public var asnDatabasePath: String?
    public var autoUpdateEnabled = false
    public var licenseKeyKeychainRef: String?
    public init() {}
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        cityDatabasePath = try c.decodeIfPresent(String.self, forKey: .cityDatabasePath)
        asnDatabasePath = try c.decodeIfPresent(String.self, forKey: .asnDatabasePath)
        autoUpdateEnabled = try c.decodeIfPresent(Bool.self, forKey: .autoUpdateEnabled) ?? autoUpdateEnabled
        licenseKeyKeychainRef = try c.decodeIfPresent(String.self, forKey: .licenseKeyKeychainRef)
    }
}

/// Optional raw datagram capture for diagnostics and fixture collection. Off by default; bounded;
/// the first thing retention deletes. Files live under `<Store>/captures/`.
public struct DiagnosticCaptureConfiguration: Codable, Sendable, Hashable {
    public var enabled = false
    public var maxBytes: Int64 = 50_000_000
    public var maxDatagrams = 50_000
    public init() {}
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? enabled
        maxBytes = try c.decodeIfPresent(Int64.self, forKey: .maxBytes) ?? maxBytes
        maxDatagrams = try c.decodeIfPresent(Int.self, forKey: .maxDatagrams) ?? maxDatagrams
    }
}

public struct PrivacyConfiguration: Codable, Sendable, Hashable {
    public var externalLookupsEnabled = false
    public var redactInternalIPsInExports = false
    public var redactMACsInExports = true
    public var redactHostnamesInExports = false
    public var redactUsernamesInExports = true
    public var diagnosticsIncludeTelemetry = false
    public init() {}
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        externalLookupsEnabled = try c.decodeIfPresent(Bool.self, forKey: .externalLookupsEnabled) ?? externalLookupsEnabled
        redactInternalIPsInExports = try c.decodeIfPresent(Bool.self, forKey: .redactInternalIPsInExports) ?? redactInternalIPsInExports
        redactMACsInExports = try c.decodeIfPresent(Bool.self, forKey: .redactMACsInExports) ?? redactMACsInExports
        redactHostnamesInExports = try c.decodeIfPresent(Bool.self, forKey: .redactHostnamesInExports) ?? redactHostnamesInExports
        redactUsernamesInExports = try c.decodeIfPresent(Bool.self, forKey: .redactUsernamesInExports) ?? redactUsernamesInExports
        diagnosticsIncludeTelemetry = try c.decodeIfPresent(Bool.self, forKey: .diagnosticsIncludeTelemetry) ?? diagnosticsIncludeTelemetry
    }
}

/// The collector's whole configuration. Stored in SQLite (`config`) and mirrored to a bootstrap JSON
/// file so the collector can start before the database is opened.
public struct CollectorConfiguration: Codable, Sendable, Hashable {
    public static let schemaVersion = 1

    public var schemaVersion = CollectorConfiguration.schemaVersion
    public var collectionEnabled = false
    public var launchAtLogin = false
    public var setupCompleted = false
    public var storageRoot: String
    public var budgetBytes: Int64 = 25 * 1_000_000_000
    public var allocation = BudgetAllocation()
    public var safetyThreshold = SafetyThreshold()
    public var listeners = ListenerConfiguration.defaults
    /// Only accept telemetry from these addresses when non-empty.
    public var allowedExporterAddresses: [String] = []
    public var internalNetworks: [String] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
    public var trustedResolvers: [String] = []
    public var geoIP = GeoIPConfiguration()
    public var privacy = PrivacyConfiguration()
    public var diagnosticCapture = DiagnosticCaptureConfiguration()
    public var liveMaxRecordsPerSecond = 200
    public var hotBufferSeconds = 120
    public var hotBufferMaxRecords = 200_000
    public var rawRetentionDays = 7
    public var compactAfterDays = 30
    public var demoWorkspace = false
    public var diagnosticsVerbose = false
    public var notificationsEnabled = true

    public init(storageRoot: String) { self.storageRoot = storageRoot }

    /// Tolerant decoding: any key missing from an older (or newer) file keeps its default, so upgrades and
    /// downgrades never reset the user's configuration. Unknown keys are ignored.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        storageRoot = try c.decodeIfPresent(String.self, forKey: .storageRoot) ?? StorageLocations.defaultStorageRoot().path
        schemaVersion = try c.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? Self.schemaVersion
        collectionEnabled = try c.decodeIfPresent(Bool.self, forKey: .collectionEnabled) ?? collectionEnabled
        launchAtLogin = try c.decodeIfPresent(Bool.self, forKey: .launchAtLogin) ?? launchAtLogin
        setupCompleted = try c.decodeIfPresent(Bool.self, forKey: .setupCompleted) ?? setupCompleted
        budgetBytes = try c.decodeIfPresent(Int64.self, forKey: .budgetBytes) ?? budgetBytes
        allocation = try c.decodeIfPresent(BudgetAllocation.self, forKey: .allocation) ?? allocation
        safetyThreshold = try c.decodeIfPresent(SafetyThreshold.self, forKey: .safetyThreshold) ?? safetyThreshold
        listeners = try c.decodeIfPresent([ListenerConfiguration].self, forKey: .listeners) ?? listeners
        allowedExporterAddresses = try c.decodeIfPresent([String].self, forKey: .allowedExporterAddresses) ?? allowedExporterAddresses
        internalNetworks = try c.decodeIfPresent([String].self, forKey: .internalNetworks) ?? internalNetworks
        trustedResolvers = try c.decodeIfPresent([String].self, forKey: .trustedResolvers) ?? trustedResolvers
        geoIP = try c.decodeIfPresent(GeoIPConfiguration.self, forKey: .geoIP) ?? geoIP
        privacy = try c.decodeIfPresent(PrivacyConfiguration.self, forKey: .privacy) ?? privacy
        diagnosticCapture = try c.decodeIfPresent(DiagnosticCaptureConfiguration.self, forKey: .diagnosticCapture) ?? diagnosticCapture
        liveMaxRecordsPerSecond = try c.decodeIfPresent(Int.self, forKey: .liveMaxRecordsPerSecond) ?? liveMaxRecordsPerSecond
        hotBufferSeconds = try c.decodeIfPresent(Int.self, forKey: .hotBufferSeconds) ?? hotBufferSeconds
        hotBufferMaxRecords = try c.decodeIfPresent(Int.self, forKey: .hotBufferMaxRecords) ?? hotBufferMaxRecords
        rawRetentionDays = try c.decodeIfPresent(Int.self, forKey: .rawRetentionDays) ?? rawRetentionDays
        compactAfterDays = try c.decodeIfPresent(Int.self, forKey: .compactAfterDays) ?? compactAfterDays
        demoWorkspace = try c.decodeIfPresent(Bool.self, forKey: .demoWorkspace) ?? demoWorkspace
        diagnosticsVerbose = try c.decodeIfPresent(Bool.self, forKey: .diagnosticsVerbose) ?? diagnosticsVerbose
        notificationsEnabled = try c.decodeIfPresent(Bool.self, forKey: .notificationsEnabled) ?? notificationsEnabled
    }

    public var internalPrefixes: [IPPrefix] { internalNetworks.compactMap(IPPrefix.init) }

    /// Validation errors, empty when the configuration is acceptable.
    public func validate() -> [String] {
        var errors: [String] = []
        if budgetBytes < StorageBudget.minimum || budgetBytes > StorageBudget.maximum {
            errors.append("Storage budget must be between 5 GB and 500 GB.")
        }
        if !allocation.isValid { errors.append("Retention allocation must sum to 100 % with at least 1 % per category.") }
        if storageRoot.isEmpty { errors.append("Storage location is required.") }
        var seen = Set<String>()
        for l in listeners {
            if l.port < 1024 { errors.append("Port \(l.port) is privileged; NetSentry supports ports 1024–65535.") }
            let key = "\(l.transport.rawValue):\(l.port)"
            if l.enabled, !seen.insert(key).inserted { errors.append("Port \(l.port)/\(l.transport.label) is used by two listeners.") }
        }
        for cidr in internalNetworks where IPPrefix(cidr) == nil { errors.append("Invalid internal network: \(cidr)") }
        for r in trustedResolvers where IPAddress(r) == nil { errors.append("Invalid resolver address: \(r)") }
        for a in allowedExporterAddresses where IPAddress(a) == nil { errors.append("Invalid exporter address: \(a)") }
        if liveMaxRecordsPerSecond < 1 || liveMaxRecordsPerSecond > 5_000 { errors.append("Live sampling rate must be 1–5000 records/s.") }
        return errors
    }
}

/// Resolves the on-disk locations shared by the dashboard and the collector.
public enum StorageLocations {
    /// Directory holding bootstrap config and small shared state (not telemetry).
    /// Both processes run un-sandboxed (ADR-002), so the plain per-user Application Support folder is shared
    /// directly. An App Group container was used here before; it made Release builds depend on a validated
    /// Team ID and, when that validation failed, the collector blocked inside `containerURL(...)` at startup.
    public static func sharedSupportDirectory() -> URL {
        realHomeDirectory().appending(path: "Library/Application Support/\(Branding.storageFolderName)", directoryHint: .isDirectory)
    }

    /// The user's actual home directory (not the sandbox container), via the passwd database.
    public static func realHomeDirectory() -> URL {
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir { return URL(fileURLWithPath: String(cString: dir), isDirectory: true) }
        return FileManager.default.homeDirectoryForCurrentUser
    }

    public static func defaultStorageRoot() -> URL { sharedSupportDirectory().appending(path: "Store", directoryHint: .isDirectory) }
    public static func demoStorageRoot() -> URL { sharedSupportDirectory().appending(path: "Store-Demo", directoryHint: .isDirectory) }
    public static func bootstrapConfigURL() -> URL { sharedSupportDirectory().appending(path: "collector.json") }

    public static func defaultConfiguration() -> CollectorConfiguration {
        CollectorConfiguration(storageRoot: defaultStorageRoot().path)
    }
}
