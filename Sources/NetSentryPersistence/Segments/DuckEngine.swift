import DuckDB
import Foundation
import NetSentryCore

/// Thin wrapper over an embedded DuckDB instance. One engine per process; connections are cheap.
/// All SQL that embeds user- or exporter-derived strings goes through `DuckEngine.literal`.
public final class DuckEngine: @unchecked Sendable {
    public let database: Database
    public let connection: Connection

    public init(memoryLimit: String = "512MB", threads: Int = 2, temporaryDirectory: URL? = nil) throws {
        let config = try Database.Configuration()
        try config.setValue(memoryLimit, forKey: "memory_limit")
        try config.setValue("\(threads)", forKey: "threads")
        if let temporaryDirectory { try config.setValue(temporaryDirectory.path, forKey: "temp_directory") }
        database = try Database(store: .inMemory, configuration: config)
        connection = try database.connect()
        try connection.execute("SET enable_progress_bar = false")
        // Note: `enable_object_cache` was measured 6× slower for paged reads over 200 segments (nsprobe); left off.
    }

    public func newConnection() throws -> Connection { try database.connect() }

    @discardableResult
    public func execute(_ sql: String) throws -> ResultSet { try connection.query(sql) }

    // The connection and result set must outlive every column read: in optimized builds ARC released them
    // right after the last syntactic use, and the column then read freed memory (EXC_BAD_ACCESS in
    // `ResultSet.element(forColumn:at:)`). `withExtendedLifetime` pins both for the duration of the read.
    public func scalarInt64(_ sql: String, on conn: Connection? = nil) throws -> Int64? {
        let c = conn ?? connection
        let r = try c.query(sql)
        return withExtendedLifetime((c, r)) {
            guard r.rowCount > 0 else { return nil }
            let col = r[0].cast(to: Int64.self)
            return col[0]
        }
    }

    public func scalarString(_ sql: String) throws -> String? {
        let c = connection
        let r = try c.query(sql)
        return withExtendedLifetime((c, r)) {
            guard r.rowCount > 0 else { return nil }
            let col = r[0].cast(to: String.self)
            return col[0]
        }
    }

    /// SQL string literal with single quotes escaped (for file paths in COPY/read_parquet).
    public static func literal(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "''") + "'" }

    /// `[ 'a', 'b' ]` list literal of paths.
    public static func pathList(_ paths: [String]) -> String { "[" + paths.map(literal).joined(separator: ", ") + "]" }
}
