// swift-tools-version: 6.0
// NetSentryKit — all shared modules for the NetSentry dashboard and collector.
// Module boundaries are enforced by target dependencies (see docs/modules-and-repository.md).
import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .enableUpcomingFeature("ExistentialAny"),
]

let package = Package(
    name: "NetSentryKit",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "NetSentryCore", targets: ["NetSentryCore"]),
        .library(name: "NetSentryIPC", targets: ["NetSentryIPC"]),
        .library(name: "NetSentryIPFIX", targets: ["NetSentryIPFIX"]),
        .library(name: "NetSentrySyslog", targets: ["NetSentrySyslog"]),
        .library(name: "NetSentryPersistence", targets: ["NetSentryPersistence"]),
        .library(name: "NetSentryDevTools", targets: ["NetSentryDevTools"]),
        .library(name: "NetSentryAnalytics", targets: ["NetSentryAnalytics"]),
        .library(name: "NetSentryEnrichment", targets: ["NetSentryEnrichment"]),
        .library(name: "NetSentryDetection", targets: ["NetSentryDetection"]),
        .library(name: "NetSentryCorrelation", targets: ["NetSentryCorrelation"]),
        .library(name: "NetSentryExport", targets: ["NetSentryExport"]),
        .executable(name: "nsgen", targets: ["nsgen"]),
        .executable(name: "nsprobe", targets: ["nsprobe"]),
    ],
    dependencies: [
        // DuckDB: embedded analytical engine that writes and reads Parquet with no runtime
        // downloads. See docs/adr/ADR-001-architecture.md, decision D5.
        .package(url: "https://github.com/duckdb/duckdb-swift", exact: "1.1.3"),
    ],
    targets: [
        .target(name: "NetSentryCore", swiftSettings: swiftSettings),
        .target(name: "NetSentryIPC", dependencies: ["NetSentryCore"], swiftSettings: swiftSettings),
        .target(name: "NetSentryIPFIX", dependencies: ["NetSentryCore"], swiftSettings: swiftSettings),
        .target(name: "NetSentrySyslog", dependencies: ["NetSentryCore"], swiftSettings: swiftSettings),
        // Thin system-library shim so Swift code can call libsqlite3 shipped with macOS.
        .systemLibrary(name: "CSQLite", path: "Sources/CSQLite"),
        .target(
            name: "NetSentryPersistence",
            dependencies: [
                "NetSentryCore",
                "CSQLite",
                .product(name: "DuckDB", package: "duckdb-swift"),
            ],
            swiftSettings: swiftSettings
        ),
        .target(
            name: "NetSentryAnalytics",
            dependencies: ["NetSentryCore", "NetSentryPersistence", .product(name: "DuckDB", package: "duckdb-swift")],
            swiftSettings: swiftSettings
        ),
        .target(name: "NetSentryEnrichment", dependencies: ["NetSentryCore", "NetSentryPersistence"], swiftSettings: swiftSettings),
        .target(name: "NetSentryDetection", dependencies: ["NetSentryCore", "NetSentryPersistence"], swiftSettings: swiftSettings),
        .target(name: "NetSentryCorrelation", dependencies: ["NetSentryCore", "NetSentryPersistence", "NetSentryAnalytics"], swiftSettings: swiftSettings),
        .target(
            name: "NetSentryDevTools",
            dependencies: ["NetSentryCore", "NetSentryIPFIX", "NetSentrySyslog"],
            swiftSettings: swiftSettings
        ),
        .executableTarget(name: "nsgen", dependencies: ["NetSentryCore", "NetSentryDevTools"], path: "Tools/nsgen", swiftSettings: swiftSettings),
        .executableTarget(name: "nsprobe", dependencies: ["NetSentryAnalytics", "NetSentryPersistence", "NetSentryIPFIX", "NetSentryDevTools"], path: "Tools/nsprobe"),
        .testTarget(name: "NetSentryCoreTests", dependencies: ["NetSentryCore"]),
        .testTarget(name: "NetSentryIPCTests", dependencies: ["NetSentryIPC"]),
        .testTarget(name: "NetSentryIPFIXTests", dependencies: ["NetSentryIPFIX", "NetSentryDevTools"]),
        .testTarget(name: "NetSentrySyslogTests", dependencies: ["NetSentrySyslog", "NetSentryDevTools"], resources: [.copy("../../Fixtures/syslog")]),
        .testTarget(name: "NetSentryPersistenceTests", dependencies: ["NetSentryPersistence", "NetSentryDevTools"]),
        .testTarget(name: "NetSentryAnalyticsTests", dependencies: ["NetSentryAnalytics", "NetSentryDevTools"]),
        .testTarget(name: "NetSentryEnrichmentTests", dependencies: ["NetSentryEnrichment", "NetSentryDevTools"]),
        .testTarget(name: "NetSentryDetectionTests", dependencies: ["NetSentryDetection", "NetSentryDevTools"]),
        .target(name: "NetSentryExport", dependencies: ["NetSentryCore", "NetSentryDetection", "NetSentryCorrelation"]),
        .testTarget(name: "NetSentryCorrelationTests", dependencies: ["NetSentryCorrelation", "NetSentryDevTools"]),
        .testTarget(name: "NetSentryExportTests", dependencies: ["NetSentryExport", "NetSentryAnalytics"]),
        .testTarget(name: "NetSentryBenchmarks", dependencies: ["NetSentryAnalytics", "NetSentryPersistence", "NetSentryIPFIX", "NetSentryDevTools"]),
    ],
    swiftLanguageModes: [.v6]
)
