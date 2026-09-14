import XCTest
@testable import NetSentryPersistence
import NetSentryCore

/// The collector shares one `MetaStore` connection between several actors (storage, entity resolver, alert
/// store) and the dashboard's read engine queries the manifest while another actor prunes segments. The
/// wrapper must therefore be safe to call from many threads at once; this reproduces the crash seen in the
/// Overview loader (SQLite heap corruption under `SQLITE_OPEN_NOMUTEX`).
final class SQLiteConcurrencyTests: XCTestCase {
    func testConcurrentQueriesAndWritesFromManyTasksDoNotCorruptTheConnection() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "netsentry-sqlite-conc-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let meta = try MetaStore(root: root)
        let db = meta.db
        try db.run("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)")
        let deleted = try await withThrowingTaskGroup(of: Int.self) { group in
            for worker in 0..<8 {
                group.addTask {
                    var removed = 0
                    for i in 0..<300 {
                        try db.run("INSERT INTO t (v) VALUES (?)", ["worker-\(worker)-\(i)-\(String(repeating: "x", count: 200))"])
                        let rows = try db.query("SELECT COUNT(*), SUM(LENGTH(v)) FROM t WHERE v LIKE ?", ["worker-\(worker)-%"])
                        XCTAssertEqual(rows.count, 1)
                        _ = try db.query("SELECT id, v FROM t ORDER BY id DESC LIMIT 20")
                        if i % 50 == 0 {
                            removed += try db.transaction { try db.run("DELETE FROM t WHERE id IN (SELECT id FROM t WHERE v LIKE ? LIMIT 5)", ["worker-\(worker)-%"]) }
                        }
                    }
                    return removed
                }
            }
            // A concurrent reader on a second, read-only connection (the dashboard).
            group.addTask {
                let ro = try MetaStore(root: root, readOnly: true)
                for _ in 0..<200 { _ = try ro.db.query("SELECT COUNT(*) FROM t"); _ = try await ro.segments(kind: .flows, from: .init(seconds: 0), to: .now, origin: .live) }
                return 0
            }
            return try await group.reduce(0, +)
        }
        let total = try db.scalar("SELECT COUNT(*) FROM t").int64 ?? 0
        XCTAssertEqual(total, Int64(8 * 300 - deleted))
        XCTAssertEqual(try db.scalar("PRAGMA integrity_check").string, "ok")
        try db.run("PRAGMA integrity_check")
    }
}
