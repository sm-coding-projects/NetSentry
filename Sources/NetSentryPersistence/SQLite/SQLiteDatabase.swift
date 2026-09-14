import CSQLite
import Foundation
import NetSentryCore

public enum SQLiteError: Error, LocalizedError {
    case open(String)
    case prepare(String, sql: String)
    case step(String, sql: String)
    case bind(String)
    case busy
    case corrupt(String)
    case migration(String)

    public var errorDescription: String? {
        switch self {
        case .open(let m): "Could not open database: \(m)"
        case .prepare(let m, let sql): "SQL prepare failed: \(m) [\(sql.prefix(120))]"
        case .step(let m, let sql): "SQL execution failed: \(m) [\(sql.prefix(120))]"
        case .bind(let m): "SQL bind failed: \(m)"
        case .busy: "Database busy"
        case .corrupt(let m): "Database integrity check failed: \(m)"
        case .migration(let m): "Migration failed: \(m)"
        }
    }
}

/// Values that can be bound to a statement. Values are always bound, never interpolated.
public enum SQLValue: Sendable, Hashable {
    case null
    case integer(Int64)
    case real(Double)
    case text(String)
    case blob(Data)

    public var int64: Int64? { if case .integer(let v) = self { return v }; return nil }
    public var double: Double? {
        switch self { case .real(let v): return v; case .integer(let v): return Double(v); default: return nil }
    }
    public var string: String? { if case .text(let v) = self { return v }; return nil }
    public var data: Data? { if case .blob(let v) = self { return v }; return nil }
    public var isNull: Bool { if case .null = self { return true }; return false }
}

public protocol SQLBindable: Sendable { var sqlValue: SQLValue { get } }
extension Int: SQLBindable { public var sqlValue: SQLValue { .integer(Int64(self)) } }
extension Int32: SQLBindable { public var sqlValue: SQLValue { .integer(Int64(self)) } }
extension Int64: SQLBindable { public var sqlValue: SQLValue { .integer(self) } }
extension UInt16: SQLBindable { public var sqlValue: SQLValue { .integer(Int64(self)) } }
extension UInt32: SQLBindable { public var sqlValue: SQLValue { .integer(Int64(self)) } }
extension UInt64: SQLBindable { public var sqlValue: SQLValue { .integer(Int64(bitPattern: self)) } }
extension UInt8: SQLBindable { public var sqlValue: SQLValue { .integer(Int64(self)) } }
extension Double: SQLBindable { public var sqlValue: SQLValue { .real(self) } }
extension String: SQLBindable { public var sqlValue: SQLValue { .text(self) } }
extension Data: SQLBindable { public var sqlValue: SQLValue { .blob(self) } }
extension Bool: SQLBindable { public var sqlValue: SQLValue { .integer(self ? 1 : 0) } }
extension Timestamp: SQLBindable { public var sqlValue: SQLValue { .integer(microseconds) } }
extension IPAddress: SQLBindable { public var sqlValue: SQLValue { .text(description) } }
extension SQLValue: SQLBindable { public var sqlValue: SQLValue { self } }
extension Optional: SQLBindable where Wrapped: SQLBindable {
    public var sqlValue: SQLValue { self?.sqlValue ?? .null }
}

/// A row returned by a query, addressable by column index or name.
public struct SQLRow: Sendable {
    public let columns: [String]
    public let values: [SQLValue]
    public subscript(_ index: Int) -> SQLValue { values[index] }
    public subscript(_ name: String) -> SQLValue {
        guard let i = columns.firstIndex(of: name) else { return .null }
        return values[i]
    }
    public func int64(_ name: String) -> Int64? { self[name].int64 }
    public func int(_ name: String) -> Int? { self[name].int64.map(Int.init) }
    public func string(_ name: String) -> String? { self[name].string }
    public func double(_ name: String) -> Double? { self[name].double }
    public func bool(_ name: String) -> Bool { (self[name].int64 ?? 0) != 0 }
    public func timestamp(_ name: String) -> Timestamp? { self[name].int64.map { Timestamp(microseconds: $0) } }
    public func data(_ name: String) -> Data? { self[name].data }
}

/// Thin, synchronous wrapper over one `sqlite3*` connection. Not thread-safe by itself; owners
/// (actors) serialize access. WAL mode allows a reader process to coexist with the writer.
/// One connection, safe to use from any thread or actor. Several actors share a connection in both processes
/// (storage manager, entity resolver, alert store in the collector; read engine and manifest pruning in the
/// dashboard), so every entry point takes a recursive lock and the handle is opened in serialized mode.
/// Without this, concurrent `async let` queries corrupted the SQLite heap (SIGSEGV in `sqlite3DbMallocRaw`).
public final class SQLiteDatabase: @unchecked Sendable {
    private var db: OpaquePointer?
    public let path: String
    private var statementCache: [String: OpaquePointer] = [:]
    private let log = Log.logger("sqlite")
    private let lock = NSRecursiveLock()

    public init(path: String, readOnly: Bool = false) throws {
        self.path = path
        var flags = readOnly ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)
        flags |= SQLITE_OPEN_FULLMUTEX
        var handle: OpaquePointer?
        let rc = sqlite3_open_v2(path, &handle, flags, nil)
        guard rc == SQLITE_OK, let h = handle else {
            let msg = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "rc=\(rc)"
            if let h = handle { sqlite3_close_v2(h) }
            throw SQLiteError.open(msg)
        }
        db = h
        sqlite3_busy_timeout(h, 5_000)
        if !readOnly {
            try execute("PRAGMA journal_mode = WAL")
            try execute("PRAGMA synchronous = NORMAL")
            try execute("PRAGMA wal_autocheckpoint = 4000")
            try execute("PRAGMA temp_store = MEMORY")
        }
        try execute("PRAGMA foreign_keys = ON")
        if path != ":memory:", !readOnly {
            chmod(path, 0o600)
        }
    }

    deinit { close() }

    public func close() {
        lock.lock(); defer { lock.unlock() }
        for (_, s) in statementCache { sqlite3_finalize(s) }
        statementCache.removeAll()
        if let d = db { sqlite3_close_v2(d); db = nil }
    }

    private func prepared(_ sql: String) throws -> OpaquePointer {
        if let s = statementCache[sql] {
            sqlite3_reset(s)
            sqlite3_clear_bindings(s)
            return s
        }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v3(db, sql, -1, UInt32(SQLITE_PREPARE_PERSISTENT), &stmt, nil) == SQLITE_OK, let s = stmt else {
            throw SQLiteError.prepare(String(cString: sqlite3_errmsg(db)), sql: sql)
        }
        if statementCache.count > 256, let victim = statementCache.keys.first {
            sqlite3_finalize(statementCache.removeValue(forKey: victim))
        }
        statementCache[sql] = s
        return s
    }

    private func bind(_ params: [any SQLBindable], to stmt: OpaquePointer) throws {
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for (i, p) in params.enumerated() {
            let idx = Int32(i + 1)
            let rc: Int32
            switch p.sqlValue {
            case .null: rc = sqlite3_bind_null(stmt, idx)
            case .integer(let v): rc = sqlite3_bind_int64(stmt, idx, v)
            case .real(let v): rc = sqlite3_bind_double(stmt, idx, v)
            case .text(let v): rc = sqlite3_bind_text(stmt, idx, v, -1, transient)
            case .blob(let v): rc = v.withUnsafeBytes { sqlite3_bind_blob(stmt, idx, $0.baseAddress, Int32(v.count), transient) }
            }
            guard rc == SQLITE_OK else { throw SQLiteError.bind(String(cString: sqlite3_errmsg(db))) }
        }
    }

    /// Executes one or more statements without parameters (DDL, PRAGMA).
    public func execute(_ sql: String) throws {
        lock.lock(); defer { lock.unlock() }
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &err)
        if rc != SQLITE_OK {
            let m = err.map { String(cString: $0) } ?? "rc=\(rc)"
            sqlite3_free(err)
            throw SQLiteError.step(m, sql: sql)
        }
    }

    /// Runs a parameterized statement that returns no rows.
    @discardableResult
    public func run(_ sql: String, _ params: [any SQLBindable] = []) throws -> Int {
        lock.lock(); defer { lock.unlock() }
        let stmt = try prepared(sql)
        try bind(params, to: stmt)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE || rc == SQLITE_ROW else {
            if rc == SQLITE_BUSY { throw SQLiteError.busy }
            throw SQLiteError.step(String(cString: sqlite3_errmsg(db)), sql: sql)
        }
        sqlite3_reset(stmt)
        return Int(sqlite3_changes(db))
    }

    public var lastInsertRowID: Int64 { lock.lock(); defer { lock.unlock() }; return sqlite3_last_insert_rowid(db) }

    /// Runs a query and returns all rows.
    public func query(_ sql: String, _ params: [any SQLBindable] = []) throws -> [SQLRow] {
        var rows: [SQLRow] = []
        try query(sql, params) { rows.append($0); return true }
        return rows
    }

    /// Streams rows; return false from the handler to stop early.
    public func query(_ sql: String, _ params: [any SQLBindable] = [], _ handler: (SQLRow) throws -> Bool) throws {
        lock.lock(); defer { lock.unlock() }
        let stmt = try prepared(sql)
        try bind(params, to: stmt)
        defer { sqlite3_reset(stmt) }
        let n = Int(sqlite3_column_count(stmt))
        let columns = (0..<n).map { String(cString: sqlite3_column_name(stmt, Int32($0))) }
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return }
            guard rc == SQLITE_ROW else {
                if rc == SQLITE_BUSY { throw SQLiteError.busy }
                throw SQLiteError.step(String(cString: sqlite3_errmsg(db)), sql: sql)
            }
            var values: [SQLValue] = []
            values.reserveCapacity(n)
            for i in 0..<n {
                let c = Int32(i)
                switch sqlite3_column_type(stmt, c) {
                case SQLITE_INTEGER: values.append(.integer(sqlite3_column_int64(stmt, c)))
                case SQLITE_FLOAT: values.append(.real(sqlite3_column_double(stmt, c)))
                case SQLITE_TEXT: values.append(.text(String(cString: sqlite3_column_text(stmt, c))))
                case SQLITE_BLOB:
                    let len = Int(sqlite3_column_bytes(stmt, c))
                    if let p = sqlite3_column_blob(stmt, c), len > 0 { values.append(.blob(Data(bytes: p, count: len))) } else { values.append(.blob(Data())) }
                default: values.append(.null)
                }
            }
            if try !handler(SQLRow(columns: columns, values: values)) { return }
        }
    }

    public func scalar(_ sql: String, _ params: [any SQLBindable] = []) throws -> SQLValue {
        var out: SQLValue = .null
        try query(sql, params) { out = $0[0]; return false }
        return out
    }

    /// Runs `body` inside a transaction (IMMEDIATE, so writers fail fast instead of deadlocking).
    public func transaction<T>(_ body: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        try execute("BEGIN IMMEDIATE")
        do {
            let r = try body()
            try execute("COMMIT")
            return r
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
    }

    public func quickCheck() throws {
        let r = try scalar("PRAGMA quick_check").string ?? "unknown"
        guard r == "ok" else { throw SQLiteError.corrupt(r) }
    }

    public func checkpoint() { lock.lock(); defer { lock.unlock() }; sqlite3_wal_checkpoint_v2(db, nil, SQLITE_CHECKPOINT_PASSIVE, nil, nil) }

    /// Online backup to `destinationPath` (used for meta.sqlite daily backups and settings export).
    public func backup(to destinationPath: String) throws {
        lock.lock(); defer { lock.unlock() }
        let dest = try SQLiteDatabase(path: destinationPath)
        guard let b = sqlite3_backup_init(dest.db, "main", db, "main") else {
            throw SQLiteError.open(String(cString: sqlite3_errmsg(dest.db)))
        }
        var rc = SQLITE_OK
        repeat { rc = sqlite3_backup_step(b, 256) } while rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED
        sqlite3_backup_finish(b)
        guard rc == SQLITE_DONE else { throw SQLiteError.step("backup rc=\(rc)", sql: "backup") }
    }
}
