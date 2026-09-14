import XCTest
@testable import NetSentryPersistence
import NetSentryCore

final class MetaStoreTests: XCTestCase {
    private func tempRoot() -> URL {
        let u = FileManager.default.temporaryDirectory.appending(path: "netsentry-test-\(UUID().uuidString)")
        addTeardownBlock { try? FileManager.default.removeItem(at: u) }
        return u
    }

    func testMigrationsApplyAndAreIdempotent() async throws {
        let root = tempRoot()
        let store = try MetaStore(root: root)
        XCTAssertEqual(try Migrator.appliedVersions(store.db), MetaSchema.migrations.map(\.version))
        let again = try MetaStore(root: root)
        XCTAssertEqual(try Migrator.appliedVersions(again.db), MetaSchema.migrations.map(\.version))
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appending(path: "flows").path))
        let perms = try FileManager.default.attributesOfItem(atPath: root.path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o700)
    }

    func testMigrationV2RebuildsAlertsKeepingRowsAndNotes() throws {
        let root = tempRoot()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        // Build a v1 database by applying only the first migration, insert an alert with a note, then migrate to current.
        let db = try SQLiteDatabase(path: MetaStore.metaPath(root: root))
        try db.execute(MetaSchema.migrations[0].sql)
        try db.run("INSERT INTO schema_migrations (version, name, applied_at) VALUES (1, 'initial', 0)")
        try db.run("INSERT INTO alerts (id, rule_name, rule_version, severity, state, title, summary, explanation_md, created_at, updated_at, first_occurrence, last_occurrence, dedupe_key, entity_json, evidence_json, refs_json, steps_json) VALUES (42, 'r', 1, 2, 'open', 't', 's', 'e', 1, 1, 1, 1, 'k', '{}', '{}', '{}', '[]')")
        try db.run("INSERT INTO alert_notes (alert_id, created_at, text) VALUES (42, 1, 'note')")
        db.close()
        let store = try MetaStore(root: root)
        XCTAssertEqual(try Migrator.appliedVersions(store.db), MetaSchema.migrations.map(\.version))
        XCTAssertEqual(try store.db.scalar("SELECT title FROM alerts WHERE id = 42").string, "t")
        XCTAssertEqual(try store.db.scalar("SELECT text FROM alert_notes WHERE alert_id = 42").string, "note")
        // The rebuilt table accepts alerts for clients that do not exist as rows.
        try store.db.run("INSERT INTO alerts (rule_name, rule_version, severity, state, title, summary, explanation_md, created_at, updated_at, first_occurrence, last_occurrence, dedupe_key, client_id, entity_json, evidence_json, refs_json, steps_json) VALUES ('r', 1, 2, 'open', 't', 's', 'e', 1, 1, 1, 1, 'k2', 999, '{}', '{}', '{}', '[]')")
        XCTAssertEqual(try store.db.scalar("SELECT COUNT(*) FROM alerts").int64, 2)
        try store.db.quickCheck()
        XCTAssertEqual(try store.db.scalar("PRAGMA foreign_keys").int64, 1, "foreign keys are re-enabled after migrating")
    }

    func testRefusesNewerSchema() throws {
        let root = tempRoot()
        let store = try MetaStore(root: root)
        try store.db.run("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)", [999, "future", 0])
        XCTAssertThrowsError(try Migrator.migrate(store.db))
    }

    func testConfigurationRoundTripAndHistory() async throws {
        let store = try MetaStore(root: tempRoot())
        let none = try await store.loadConfiguration()
        XCTAssertNil(none)
        var c = CollectorConfiguration(storageRoot: "/x")
        try await store.saveConfiguration(c)
        c.budgetBytes = 50_000_000_000
        try await store.saveConfiguration(c)
        let loaded = try await store.loadConfiguration()
        XCTAssertEqual(loaded, c)
        XCTAssertEqual(try store.db.scalar("SELECT COUNT(*) FROM config_history").int64, 2)
    }

    func testGapsOpenAndClose() async throws {
        let store = try MetaStore(root: tempRoot())
        let id = try await store.openGap(kind: .sleep, reason: "test", details: ["a": "b"])
        var open = try await store.openGaps()
        XCTAssertEqual(open.count, 1); XCTAssertEqual(open[0].details["a"], "b"); XCTAssertEqual(open[0].kind, .sleep)
        try await store.closeGap(id: id)
        open = try await store.openGaps()
        XCTAssertTrue(open.isEmpty)
        let all = try await store.gaps(from: Timestamp(microseconds: 0), to: .now)
        XCTAssertEqual(all.count, 1); XCTAssertNotNil(all[0].end)
    }

    func testExporterUpsert() async throws {
        let store = try MetaStore(root: tempRoot())
        let key = ExporterKey(address: IPAddress("192.168.1.1")!, observationDomain: 7)
        let a = try await store.upsertExporter(kind: .ipfix, key: key, seenAt: .now, lastSequence: 10, restarted: false)
        let b = try await store.upsertExporter(kind: .ipfix, key: key, seenAt: .now, lastSequence: 3, restarted: true)
        XCTAssertEqual(a, b)
        XCTAssertEqual(try store.db.scalar("SELECT restarts FROM exporters WHERE id = ?", [a]).int64, 1)
    }

    func testParameterBindingNeverInterpolates() throws {
        let store = try MetaStore(root: tempRoot())
        let evil = "x'); DROP TABLE gaps; --"
        try store.db.run("INSERT INTO gaps (start_ts, kind, reason) VALUES (?, ?, ?)", [1, "sleep", evil])
        XCTAssertEqual(try store.db.scalar("SELECT reason FROM gaps").string, evil)
        XCTAssertEqual(try store.db.scalar("SELECT COUNT(*) FROM gaps").int64, 1)
    }

    func testBackupAndBootstrap() throws {
        let root = tempRoot()
        let store = try MetaStore(root: root)
        let url = try store.db.backup(to: root.appending(path: "b.sqlite").path)
        _ = url
        XCTAssertTrue(FileManager.default.fileExists(atPath: root.appending(path: "b.sqlite").path))
        let cfgURL = root.appending(path: "collector.json")
        let c = CollectorConfiguration(storageRoot: root.path)
        try BootstrapConfig.save(c, to: cfgURL)
        XCTAssertEqual(BootstrapConfig.load(from: cfgURL), c)
    }
}
