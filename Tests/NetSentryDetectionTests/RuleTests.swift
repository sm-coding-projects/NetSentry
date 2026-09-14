import XCTest
@testable import NetSentryDetection
import NetSentryCore
import NetSentryPersistence

/// Fixture-driven tests: every rule is triggered by a synthetic batch and checked for a correct,
/// explainable finding, plus a negative case that must stay silent.
final class RuleTests: XCTestCase {
    private var meta: MetaStore!
    private var state: SQLiteRuleState!
    private let t0 = Timestamp(seconds: 1_789_000_000)
    private let exporter = ExporterKey(address: IPAddress("192.168.99.1")!, observationDomain: 0)

    override func setUp() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "netsentry-rules-\(UUID().uuidString)")
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        meta = try MetaStore(root: root)
        state = SQLiteRuleState(meta: meta)
    }

    private func ctx(_ rule: any DetectionRule, params: [String: Double] = [:], now: Timestamp? = nil, expected: Set<String> = [], resolvers: [String] = []) -> DetectionContext {
        var c = RuleConfiguration(); c.parameters = params
        return DetectionContext(now: now ?? t0, configuration: c, trustedResolvers: Set(resolvers.compactMap(IPAddress.init)), internalPrefixes: [IPPrefix("192.168.99.0/24")!, IPPrefix("192.168.20.0/24")!],
                                clientName: { "client-\($0)" }, expected: { expected.contains("\($0)|\($1)|\($2)|\($3)") })
    }

    private func flow(_ i: Int, src: String = "192.168.99.31", dst: String = "203.0.113.9", sport: UInt16 = 40_000, dport: UInt16 = 443, proto: UInt8 = 6, octets: UInt64 = 5_000, packets: UInt64 = 10,
                      at: Timestamp? = nil, client: Int64? = 7, direction: TrafficDirection = .outbound, country: String? = "DE", asn: UInt32? = 3320, srcVLAN: UInt16? = nil, dstVLAN: UInt16? = nil) -> FlowRecord {
        let t = at ?? Timestamp(microseconds: t0.microseconds + Int64(i) * 1_000_000)
        var f = FlowRecord(exporter: exporter, exportSequence: UInt32(i), receivedAt: t, exportTime: t, startTime: t, endTime: t + .milliseconds(100), srcIP: IPAddress(src)!, dstIP: IPAddress(dst)!)
        f.id = Int64(1_000 + i); f.srcPort = sport; f.dstPort = dport; f.protocolNumber = proto; f.octets = octets; f.packets = packets
        f.enrichment.direction = direction; f.enrichment.srcInternal = direction != .inbound; f.enrichment.dstInternal = direction == .inbound || direction == .lan
        f.enrichment.srcClientID = client; f.enrichment.dstCountry = country; f.enrichment.dstASN = asn; f.enrichment.dstOrganization = asn.map { "AS\($0) Org" }
        f.enrichment.service = dport == 443 ? "https" : nil; f.srcVLAN = srcVLAN; f.dstVLAN = dstVLAN
        return f
    }

    private func event(_ i: Int, type: EventType = .firewall, action: FirewallAction? = .deny, src: String = "203.0.113.99", dst: String = "192.168.99.1", dport: UInt16 = 22, at: Timestamp? = nil, message: String = "") -> SyslogEvent {
        let t = at ?? Timestamp(microseconds: t0.microseconds + Int64(i) * 1_000_000)
        var e = SyslogEvent(receivedAt: t, sourceIP: exporter.address, transport: .udp, message: message, raw: message)
        e.id = Int64(5_000 + i); e.eventType = type; e.action = action; e.srcIP = IPAddress(src); e.dstIP = IPAddress(dst); e.dstPort = dport; e.ruleName = "WAN_LOCAL-D-4001"
        e.enrichment.srcInternal = IPAddress(src)!.isPrivate; e.enrichment.dstInternal = IPAddress(dst)!.isPrivate
        return e
    }

    // MARK: First-seen

    func testFirstSeenRulesRespectLearningPeriodAndExpectations() throws {
        var rule = FirstSeenRule(kind: .destination)
        let learningEnd = t0 + .seconds(4 * 86_400)
        // Day 0: history only (learning period).
        XCTAssertEqual(try rule.evaluate(flows: [flow(0, dst: "203.0.113.9", octets: 50_000)], events: [], context: ctx(rule), state: state).count, 0)
        // Day 4: a repeat of a known destination stays quiet; a new one alerts with evidence and steps.
        let known = try rule.evaluate(flows: [flow(1, dst: "203.0.113.9", octets: 50_000, at: learningEnd)], events: [], context: ctx(rule, now: learningEnd), state: state)
        XCTAssertEqual(known.count, 0)
        let fresh = try rule.evaluate(flows: [flow(2, dst: "198.51.100.5", octets: 50_000, at: learningEnd)], events: [], context: ctx(rule, now: learningEnd), state: state)
        XCTAssertEqual(fresh.count, 1)
        let f = fresh[0]
        XCTAssertEqual(f.ruleName, "first-seen-destination"); XCTAssertEqual(f.clientID, 7); XCTAssertEqual(f.entity.id, "198.51.100.5")
        XCTAssertTrue(f.title.contains("client-7")); XCTAssertTrue(f.explanation.contains("first flow")); XCTAssertEqual(f.evidence["bytes"], "50000"); XCTAssertEqual(f.flowIDs, [1002]); XCTAssertFalse(f.steps.isEmpty)
        XCTAssertEqual(f.dedupeKey, "first-seen-destination:7:198.51.100.5")
        // Tiny first contact below minBytes is ignored; expected destinations are ignored.
        XCTAssertEqual(try rule.evaluate(flows: [flow(3, dst: "198.51.100.6", octets: 10, at: learningEnd)], events: [], context: ctx(rule, now: learningEnd), state: state).count, 0)
        XCTAssertEqual(try rule.evaluate(flows: [flow(4, dst: "198.51.100.7", octets: 50_000, at: learningEnd)], events: [], context: ctx(rule, now: learningEnd, expected: ["client|7|destination|198.51.100.7"]), state: state).count, 0)
        // Country / ASN / service variants.
        var country = FirstSeenRule(kind: .country)
        _ = try country.evaluate(flows: [flow(5, country: "DE")], events: [], context: ctx(country), state: state)
        XCTAssertEqual(try country.evaluate(flows: [flow(6, at: learningEnd, country: "DE")], events: [], context: ctx(country, now: learningEnd), state: state).count, 0)
        let cf = try country.evaluate(flows: [flow(7, at: learningEnd, country: "RU")], events: [], context: ctx(country, now: learningEnd), state: state)
        XCTAssertEqual(cf.count, 1); XCTAssertEqual(cf[0].entity.kind, "country"); XCTAssertEqual(cf[0].entity.id, "RU")
        var asn = FirstSeenRule(kind: .asn)
        _ = try asn.evaluate(flows: [flow(8)], events: [], context: ctx(asn), state: state)
        XCTAssertEqual(try asn.evaluate(flows: [flow(9, at: learningEnd, asn: 64512)], events: [], context: ctx(asn, now: learningEnd), state: state).first?.entity.label, "AS64512 (AS64512 Org)")
        var svc = FirstSeenRule(kind: .service)
        _ = try svc.evaluate(flows: [flow(10, dport: 443)], events: [], context: ctx(svc), state: state)
        XCTAssertEqual(try svc.evaluate(flows: [flow(11, dport: 3389, at: learningEnd)], events: [], context: ctx(svc, now: learningEnd), state: state).first?.entity.id, "tcp/3389")
    }

    // MARK: DNS

    func testUnauthorizedResolver() throws {
        var rule = UnauthorizedResolverRule()
        let c = ctx(rule, resolvers: ["192.168.99.1", "1.1.1.1"])
        XCTAssertEqual(try rule.evaluate(flows: [flow(0, dst: "1.1.1.1", dport: 53, proto: 17)], events: [], context: c, state: state).count, 0, "trusted resolver")
        let f = try rule.evaluate(flows: [flow(1, dst: "8.8.8.8", dport: 53, proto: 17), flow(2, dst: "9.9.9.9", dport: 853, proto: 6)], events: [], context: c, state: state)
        XCTAssertEqual(f.count, 2); XCTAssertEqual(f[0].severity, AlertSeverity.medium); XCTAssertEqual(f[0].evidence["resolver"], "8.8.8.8"); XCTAssertTrue(f[1].summary.contains("DNS-over-TLS"))
        XCTAssertEqual(try rule.evaluate(flows: [flow(3, dst: "8.8.8.8", dport: 53, proto: 17)], events: [], context: ctx(rule, resolvers: []), state: state).count, 0, "no trusted list configured → rule is inert")
        XCTAssertEqual(try rule.evaluate(flows: [flow(4, dst: "8.8.4.4", dport: 53, proto: 17)], events: [], context: ctx(rule, expected: ["client|7|resolver|8.8.4.4"], resolvers: ["1.1.1.1"]), state: state).count, 0)
    }

    // MARK: Scans

    func testHorizontalAndVerticalScans() throws {
        var h = PortScanRule(kind: .horizontal)
        let probes = (0..<30).map { flow($0, dst: "192.168.99.\(10 + $0)", dport: 445, octets: 60, packets: 1, direction: .lan) }
        let found = try h.evaluate(flows: probes, events: [], context: ctx(h), state: state)
        XCTAssertEqual(found.count, 1); XCTAssertEqual(found[0].severity, AlertSeverity.high); XCTAssertEqual(found[0].evidence["distinct"], "25"); XCTAssertEqual(found[0].evidence["port"], "445")
        XCTAssertTrue(found[0].title.contains("scanned 25 hosts")); XCTAssertGreaterThanOrEqual(found[0].flowIDs.count, 25)
        // Established sessions (many packets) never count.
        var h2 = PortScanRule(kind: .horizontal)
        let sessions = (0..<30).map { flow($0, dst: "192.168.99.\(10 + $0)", dport: 445, packets: 500, direction: .lan) }
        XCTAssertEqual(try h2.evaluate(flows: sessions, events: [], context: ctx(h2), state: state).count, 0)
        var v = PortScanRule(kind: .vertical)
        let vertical = (0..<25).map { flow($0, dst: "192.168.99.50", dport: UInt16(1 + $0), octets: 60, packets: 1, direction: .lan) }
        let vf = try v.evaluate(flows: vertical, events: [], context: ctx(v), state: state)
        XCTAssertEqual(vf.count, 1); XCTAssertEqual(vf[0].evidence["distinct"], "20"); XCTAssertTrue(vf[0].title.contains("20 ports on 192.168.99.50"))
        // Outside the window nothing accumulates.
        var slow = PortScanRule(kind: .vertical)
        let spread = (0..<25).map { flow($0, dst: "192.168.99.50", dport: UInt16(1 + $0), packets: 1, at: t0 + .seconds(Int64($0) * 120), direction: .lan) }
        XCTAssertEqual(try slow.evaluate(flows: spread, events: [], context: ctx(slow), state: state).count, 0)
    }

    // MARK: Denials, volume, time

    func testRepeatedDenials() throws {
        var rule = RepeatedDenialsRule()
        let denied = (0..<25).map { event($0) }
        let f = try rule.evaluate(flows: [], events: denied, context: ctx(rule), state: state)
        XCTAssertEqual(f.count, 1); XCTAssertEqual(f[0].evidence["count"], "20"); XCTAssertEqual(f[0].eventIDs.count, 20); XCTAssertTrue(f[0].explanation.contains("WAN_LOCAL-D-4001"))
        var allow = RepeatedDenialsRule()
        XCTAssertEqual(try allow.evaluate(flows: [], events: (0..<25).map { event($0, action: .allow) }, context: ctx(allow), state: state).count, 0)
    }

    func testLargeOutboundTransferAccountsForSampling() throws {
        var rule = LargeOutboundTransferRule()
        var sampled = flow(0, octets: 3_000_000); sampled.samplingInterval = 512   // ≈ 1.5 GB after correction
        let f = try rule.evaluate(flows: [sampled], events: [], context: ctx(rule), state: state)
        XCTAssertEqual(f.count, 1); XCTAssertEqual(f[0].evidence["bytes"], "\(3_000_000 * 512)"); XCTAssertTrue(f[0].explanation.contains("1:512"))
        var small = LargeOutboundTransferRule()
        XCTAssertEqual(try small.evaluate(flows: (0..<50).map { flow($0, octets: 1_000_000) }, events: [], context: ctx(small), state: state).count, 0, "50 MB total stays under 1 GB")
        var expected = LargeOutboundTransferRule()
        XCTAssertEqual(try expected.evaluate(flows: [sampled], events: [], context: ctx(expected, expected: ["client|7|destination|203.0.113.9"]), state: state).count, 0)
    }

    func testUnusualVolumeUsesClientBaselineFromRollups() async throws {
        // 48 hours of ~10 MB/hour outbound for client 7 in rollup_minute.
        var rows: [MetaStore.MinuteRollup] = []
        for h in 0..<48 { rows.append(.init(bucket: Timestamp(microseconds: t0.microseconds - Int64(48 - h) * 3_600_000_000), origin: .live, clientID: 7, direction: 1, flows: 100, packets: 10_000, bytes: 10_000_000, denied: 0, allowed: 0)) }
        try await meta.mergeMinuteRollups(rows)
        var rule = UnusualVolumeRule()
        var big = flow(0, octets: 300_000_000); big.enrichment.srcClientID = 7
        let f = try rule.evaluate(flows: [big], events: [], context: ctx(rule), state: state)
        XCTAssertEqual(f.count, 1); XCTAssertEqual(f[0].baseline?.kind, "rolling"); XCTAssertEqual(f[0].baseline?.value, 10_000_000); XCTAssertEqual(f[0].baseline?.samples, 48)
        XCTAssertTrue(f[0].title.contains("30.0×")); XCTAssertEqual(f[0].evidence["median_hour"], "10000000")
        var quiet = UnusualVolumeRule()
        var normal = flow(1, octets: 250_000_000); normal.enrichment.srcClientID = 7      // 25× median but... above minBytes; check p95 gate with a spike in history
        // Three 900 MB hours in the history lift the 95th percentile (≥ 5 % of 51 samples) to 900 MB.
        try await meta.mergeMinuteRollups((1...3).map { .init(bucket: Timestamp(microseconds: t0.microseconds - Int64($0) * 3_600_000_000 - 30_000_000), origin: .live, clientID: 7, direction: 1, flows: 1, packets: 1, bytes: 900_000_000, denied: 0, allowed: 0) })
        XCTAssertEqual(try quiet.evaluate(flows: [normal], events: [], context: ctx(quiet), state: state).count, 0, "not above the 95th percentile once history has a bigger hour")
        var noHistory = UnusualVolumeRule()
        var other = flow(2, octets: 300_000_000); other.enrichment.srcClientID = 8
        XCTAssertEqual(try noHistory.evaluate(flows: [other], events: [], context: ctx(noHistory), state: state).count, 0, "no baseline → no alert")
    }

    func testUnusualActivityTime() async throws {
        // 14 days of activity only between 08:00–18:00 local for client 7.
        var cal = Calendar(identifier: .gregorian); cal.timeZone = .current
        var rows: [MetaStore.MinuteRollup] = []
        for d in 1...14 { for h in 8..<18 {
            let day = Timestamp(microseconds: t0.microseconds - Int64(d) * 86_400_000_000)
            var comps = cal.dateComponents([.year, .month, .day], from: day.date); comps.hour = h; comps.minute = 0
            rows.append(.init(bucket: Timestamp(cal.date(from: comps)!), origin: .live, clientID: 7, direction: 1, flows: 60, packets: 600, bytes: 60_000, denied: 0, allowed: 0))
        } }
        try await meta.mergeMinuteRollups(rows)
        var rule = UnusualTimeRule()
        var night = cal.dateComponents([.year, .month, .day], from: t0.date); night.hour = 3; night.minute = 10
        let at = Timestamp(cal.date(from: night)!)
        let flows = (0..<25).map { i -> FlowRecord in var f = flow(i, at: at + .seconds(Int64(i))); f.enrichment.srcClientID = 7; return f }
        let f = try rule.evaluate(flows: flows, events: [], context: ctx(rule, now: at), state: state)
        XCTAssertEqual(f.count, 1); XCTAssertTrue(f[0].title.contains("(3:00)")); XCTAssertEqual(f[0].evidence["share_baseline"], "0.0000")
        var dayRule = UnusualTimeRule()
        var noon = cal.dateComponents([.year, .month, .day], from: t0.date); noon.hour = 12
        let atNoon = Timestamp(cal.date(from: noon)!)
        let dayFlows = (0..<25).map { i -> FlowRecord in var f = flow(i, at: atNoon + .seconds(Int64(i))); f.enrichment.srcClientID = 7; return f }
        XCTAssertEqual(try dayRule.evaluate(flows: dayFlows, events: [], context: ctx(dayRule, now: atNoon), state: state).count, 0)
    }

    // MARK: Beaconing, VLAN, IDS, collection

    func testBeaconingDetectsRegularIntervalsOnly() throws {
        var rule = BeaconingRule()
        let regular = (0..<15).map { flow($0, dst: "203.0.113.50", dport: 8443, octets: 900, at: t0 + .seconds(Int64($0) * 60)) }
        let f = try rule.evaluate(flows: regular, events: [], context: ctx(rule), state: state)
        XCTAssertEqual(f.count, 1); XCTAssertTrue(f[0].title.contains("every 60 s")); XCTAssertEqual(f[0].evidence["connections"], "12", "fires as soon as the minimum is reached"); XCTAssertEqual(f[0].flowIDs.count, 12)
        var jitter = BeaconingRule()
        var rng = SystemRandomNumberGenerator()
        var t = t0
        let irregular = (0..<15).map { i -> FlowRecord in t = t + .seconds(Int64(Int.random(in: 5...300, using: &rng))); return flow(i, dst: "203.0.113.51", dport: 8443, octets: 900, at: t) }
        XCTAssertEqual(try jitter.evaluate(flows: irregular, events: [], context: ctx(jitter, params: ["maxJitter": 0.05]), state: state).count, 0)
        var large = BeaconingRule()
        XCTAssertEqual(try large.evaluate(flows: regular.map { var x = $0; x.octets = 5_000_000; return x }, events: [], context: ctx(large), state: state).count, 0, "large transfers are not beacons")
    }

    func testUnexpectedVLANCommunication() throws {
        var rule = UnexpectedVLANRule()
        let cross = flow(0, src: "192.168.20.5", dst: "192.168.99.10", octets: 50_000, direction: .lan, srcVLAN: 20, dstVLAN: 99)
        let f = try rule.evaluate(flows: [cross], events: [], context: ctx(rule), state: state)
        XCTAssertEqual(f.count, 1); XCTAssertEqual(f[0].entity.id, "vlan20<->vlan99"); XCTAssertEqual(f[0].evidence["src_network"], "vlan20")
        var expected = UnexpectedVLANRule()
        XCTAssertEqual(try expected.evaluate(flows: [cross], events: [], context: ctx(expected, expected: ["global|*|vlan-pair|vlan20<->vlan99"]), state: state).count, 0)
        var same = UnexpectedVLANRule()
        XCTAssertEqual(try same.evaluate(flows: [flow(1, src: "192.168.99.5", dst: "192.168.99.10", octets: 50_000, direction: .lan)], events: [], context: ctx(same), state: state).count, 0, "same network from prefixes → no finding")
        var byPrefix = UnexpectedVLANRule()
        XCTAssertEqual(try byPrefix.evaluate(flows: [flow(2, src: "192.168.20.5", dst: "192.168.99.10", octets: 50_000, direction: .lan)], events: [], context: ctx(byPrefix), state: state).first?.entity.id, "192.168.20.0/24<->192.168.99.0/24")
    }

    func testIDSCorrelationAttachesFlowsWithoutClaimingCause() throws {
        var rule = IDSCorrelationRule()
        let related = flow(0, src: "203.0.113.99", dst: "192.168.99.31", dport: 22, direction: .inbound)
        var ids = event(1, type: .ids, action: .alert, src: "203.0.113.99", dst: "192.168.99.31", dport: 22, message: "[1:2001219:20] ET SCAN Potential SSH Scan")
        ids.idsSignatureID = 2001219; ids.idsSignature = "ET SCAN Potential SSH Scan"; ids.idsCategory = "Attempted Information Leak"; ids.idsSeverity = 2
        let f = try rule.evaluate(flows: [related, flow(2, dst: "8.8.8.8")], events: [ids], context: ctx(rule, now: t0 + .seconds(2)), state: state)
        XCTAssertEqual(f.count, 1); XCTAssertEqual(f[0].severity, AlertSeverity.high); XCTAssertEqual(f[0].flowIDs, [1000]); XCTAssertEqual(f[0].eventIDs, [5001])
        XCTAssertTrue(f[0].explanation.contains("not necessarily the exploit payload")); XCTAssertEqual(f[0].evidence["signature_id"], "2001219")
        var low = IDSCorrelationRule()
        var noisy = ids; noisy.idsSeverity = 4
        XCTAssertEqual(try low.evaluate(flows: [], events: [noisy], context: ctx(low), state: state).count, 0, "below minimum priority")
    }

    func testCollectionFailureFromHealth() {
        let rule = CollectionFailureRule()
        var h = HealthSnapshot(generatedAt: t0, collectorVersion: "0", collectorBuild: "0", startedAt: t0, pid: 1,
                               listeners: [ListenerStatus(kind: .ipfix, transport: .udp, port: 2055, interface: nil, state: .failed("EADDRINUSE"))],
                               exporters: [], counters: PipelineCounters(), rates: PipelineRates(), queues: [], openGaps: [], warnings: [], storage: nil, demoWorkspace: false)
        h.counters.receiveQueueDropped = 500
        let f = rule.evaluate(health: h, previous: nil, context: ctx(rule))
        XCTAssertEqual(f.count, 2)
        XCTAssertTrue(f.contains { $0.title.contains("dropped 500") && $0.explanation.contains("must not be read as quiet") })
        XCTAssertTrue(f.contains { $0.severity == AlertSeverity.critical && $0.title.contains("listener") })
        var ok = h; ok.listeners = []; ok.counters.receiveQueueDropped = 510
        XCTAssertEqual(rule.evaluate(health: ok, previous: h, context: ctx(rule)).count, 0, "10 drops since last tick is below the threshold")
    }

    // MARK: Engine, alerts, suppressions

    func testEngineRecordsDeduplicatesSuppressesAndReloadsConfiguration() async throws {
        let engine = try await DetectionEngine(meta: meta, rules: [PortScanRule(kind: .horizontal), UnauthorizedResolverRule()])
        await engine.configure(trustedResolvers: [IPAddress("1.1.1.1")!], internalPrefixes: [IPPrefix("192.168.99.0/24")!], origin: .live)
        await engine.setClientName(7, "NAS-01")
        let store = await engine.alertStore
        let probes = (0..<30).map { flow($0, dst: "192.168.99.\(10 + $0)", dport: 445, packets: 1, direction: .lan) }
        let first = await engine.evaluate(flows: probes, events: [], now: t0 + .seconds(30))
        XCTAssertEqual(first.count, 1); XCTAssertEqual(first[0].state, AlertState.open); XCTAssertEqual(first[0].occurrenceCount, 1); XCTAssertTrue(first[0].title.contains("NAS-01"))
        // Same scan again later → same alert, occurrence 2.
        let again = await engine.evaluate(flows: probes.map { var x = $0; x.startTime = x.startTime + .seconds(120); x.endTime = x.endTime + .seconds(120); return x }, events: [], now: t0 + .seconds(150))
        XCTAssertEqual(again.first?.id, first[0].id); XCTAssertEqual(again.first?.occurrenceCount, 2)
        let counts = try await store.counts()
        XCTAssertEqual(counts[.open], 1)
        // Workflow: acknowledge, note, resolve, reopen.
        try await store.setState(first[0].id, .acknowledged); try await store.addNote(first[0].id, "Known vulnerability scanner")
        try await store.setState(first[0].id, .resolved)
        let resolved = try await store.alert(id: first[0].id)
        XCTAssertNotNil(resolved?.resolvedAt)
        try await store.setState(first[0].id, .open)
        let reopened = try await store.alert(id: first[0].id)
        XCTAssertEqual(reopened?.state, AlertState.open); XCTAssertEqual(reopened?.notes.first?.text, "Known vulnerability scanner"); XCTAssertNil(reopened?.resolvedAt)
        // Suppression scoped to the client stops future findings; a stats counter records it.
        try await store.addSuppression(Suppression(id: 0, ruleName: "port-scan-horizontal", clientID: 7, vlan: nil, destination: nil, port: nil, asn: nil, country: nil, startHour: nil, endHour: nil, expiresAt: nil, reason: "authorized scanner", createdAt: t0))
        try await engine.reloadPolicy()
        let suppressed = await engine.evaluate(flows: probes.map { var x = $0; x.startTime = x.startTime + .seconds(600); x.endTime = x.endTime + .seconds(600); return x }, events: [], now: t0 + .seconds(630))
        XCTAssertEqual(suppressed.count, 0)
        let stats = await engine.stats
        XCTAssertEqual(stats.suppressed, 1); XCTAssertEqual(stats.alertsCreated, 1); XCTAssertEqual(stats.alertsUpdated, 1)
        // Disabling a rule via configuration.
        var cfg = RuleConfiguration(); cfg.enabled = false
        try await store.setRuleConfiguration("dns-unauthorized-resolver", version: 1, cfg); try await engine.reloadPolicy()
        let disabled = await engine.evaluate(flows: [flow(99, dst: "8.8.8.8", dport: 53, proto: 17)], events: [], now: t0)
        XCTAssertEqual(disabled.count, 0)
        // Rule descriptors expose parameters for the UI.
        let desc = await engine.ruleDescriptors
        XCTAssertEqual(desc.count, 2); XCTAssertTrue(desc[0].parameters.contains { $0.key == "threshold" })
        let configs = try await store.ruleConfigurations()
        XCTAssertEqual(configs["port-scan-horizontal"]?.parameters["threshold"], 25)
    }
}
