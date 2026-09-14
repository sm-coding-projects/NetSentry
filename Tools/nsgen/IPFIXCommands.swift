import Foundation
import NetSentryCore
import NetSentryDevTools

/// `nsgen ipfix` scenarios: valid UCG-shaped export, malformed datagrams, multiple exporters,
/// missing/replaced templates, sequence gaps, sustained and burst workloads.
enum IPFIXCommands {
    static func run(args: [String], opt: (String, String) -> String, has: (String) -> Bool) {
        let host = opt("host", "127.0.0.1")
        let port = UInt16(opt("port", "2055")) ?? 2055
        let scenario = opt("scenario", "steady")
        let seconds = Double(opt("seconds", "10")) ?? 10
        let rate = Double(opt("rate", "200")) ?? 200           // flow records per second
        let exporters = Int(opt("exporters", "1")) ?? 1
        let domain = UInt32(opt("domain", "0")) ?? 0
        let templateEvery = Int(opt("template-every", "20")) ?? 20   // messages between template refreshes
        let seed = UInt64(opt("seed", "1")) ?? 1
        let perMessage = Int(opt("per-message", "10")) ?? 10

        var senders = (0..<exporters).map { _ in DatagramSender(host: host, port: port) }
        for s in senders { _ = s.waitUntilReady() }
        var builders = (0..<exporters).map { i in IPFIXBuilder(observationDomain: domain + UInt32(i), sequence: UInt32(1000 * i), exportTime: UInt32(Date().timeIntervalSince1970)) }
        var sources = (0..<exporters).map { SyntheticFlowSource(seed: seed &+ UInt64($0)) }
        let fields = IPFIXBuilder.ucgFiberV4Fields
        let optFields: [IPFIXBuilder.Field] = [.init(149, 4), .init(302, 1), .init(390, 1), .init(309, 1), .init(310, 2)]
        var sent = 0, records = 0
        let start = Date()
        var msgIndex = 0
        var rng = SplitMix64(seed: seed)

        func nowMs() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }
        func templateMessage(_ i: Int, replaced: Bool = false) -> Data {
            builders[i].exportTime = UInt32(Date().timeIntervalSince1970)
            builders[i].addTemplate(id: 264, fields: replaced ? fields + [.init(58, 2)] : fields)
            builders[i].addOptionsTemplate(id: 257, scopeCount: 1, fields: optFields)
            builders[i].addDataSet(templateID: 257, records: [IPFIXBuilder.encode(fields: optFields, values: [domain + UInt32(i), 3, 3, 1, 512])])
            return builders[i].build(dataRecords: 1)
        }
        func dataMessage(_ i: Int, count: Int) -> Data {
            builders[i].exportTime = UInt32(Date().timeIntervalSince1970)
            let recs = (0..<count).map { _ in sources[i].nextRecord(endMilliseconds: nowMs() - rng.next() % 2000) }
            builders[i].addDataSet(templateID: 264, records: recs)
            return builders[i].build(dataRecords: count)
        }

        switch scenario {
        case "steady", "burst", "multi", "gaps", "missing-template", "replace-template":
            if scenario != "missing-template" { for i in 0..<exporters { senders[i].sendBlocking(templateMessage(i)); sent += 1 } }
            let interval = Double(perMessage) / rate
            var next = Date()
            while Date().timeIntervalSince(start) < seconds {
                for i in 0..<exporters {
                    var count = perMessage
                    if scenario == "burst", Int(Date().timeIntervalSince(start)) % 4 == 2 { count = perMessage * 20 }
                    if scenario == "gaps", msgIndex % 7 == 3 { builders[i].sequence &+= 5 }   // pretend 5 records were lost
                    if scenario == "missing-template", msgIndex == 15 { senders[i].sendBlocking(templateMessage(i)); sent += 1 }
                    if scenario == "replace-template", msgIndex == 25 { senders[i].sendBlocking(templateMessage(i, replaced: true)); sent += 1 }
                    senders[i].sendBlocking(dataMessage(i, count: count)); sent += 1; records += count
                    if templateEvery > 0, msgIndex % templateEvery == templateEvery - 1 { senders[i].sendBlocking(templateMessage(i)); sent += 1 }
                }
                msgIndex += 1
                next.addTimeInterval(interval)
                let sleep = next.timeIntervalSinceNow
                if sleep > 0 { usleep(useconds_t(sleep * 1_000_000)) }
            }
        case "malformed":
            var b = builders[0]
            let cases: [Data] = [
                Data(), Data([0]), Data([0, 9, 0, 20]) + Data(count: 16), Data([0, 5, 0, 1]) + Data(count: 44),
                Data([0, 10, 0, 0]) + Data(count: 12), Data([0, 10, 0xff, 0xff]) + Data(count: 12),
                Data([0, 10, 0, 20]) + Data(count: 12) + Data([1, 0, 0, 3]), Data([0, 10, 0, 20]) + Data(count: 12) + Data([1, 4, 0, 200]),
                Data([0, 10, 0, 24]) + Data(count: 12) + Data([0, 2, 0, 8, 1, 44, 0xff, 0xff]),
                Data([0, 10, 0, 28]) + Data(count: 12) + Data([0, 2, 0, 12, 0, 1, 0, 1, 0, 8, 0, 4]),
                { b.addTemplate(id: 300, fields: [.init(8, 0)]); b.addDataSet(templateID: 300, records: [Data(count: 40)]); return b.build(dataRecords: 0) }(),
                { b.addTemplate(id: 264, fields: fields); b.addDataSet(templateID: 264, records: [Data(count: 30)]); return b.build(dataRecords: 1) }(),
            ]
            for c in cases { senders[0].sendBlocking(c); sent += 1 }
            var valid = templateMessage(0)
            for _ in 0..<200 {
                var m = dataMessage(0, count: 3)
                let n = UInt64(max(m.count, 1))
                for _ in 0..<(1 + rng.next() % 3) {
                    switch rng.next() % 3 {
                    case 0: if !m.isEmpty { m[Int(rng.next() % n)] = UInt8(truncatingIfNeeded: rng.next()) }
                    case 1: m = m.prefix(Int(rng.next() % n))
                    default: m.append(contentsOf: Data((0..<Int(rng.next() % 32)).map { _ in UInt8(truncatingIfNeeded: rng.next()) }))
                    }
                }
                senders[0].sendBlocking(m); sent += 1
            }
            _ = valid; valid = Data()
        default:
            print("unknown scenario \(scenario); use steady|burst|multi|gaps|missing-template|replace-template|malformed"); exit(2)
        }
        for s in senders { s.close() }
        let secs = Date().timeIntervalSince(start)
        print("ipfix \(scenario): sent \(sent) datagrams, \(records) flow records to \(host):\(port) in \(String(format: "%.2f", secs)) s (\(Int(Double(records) / max(secs, 0.001))) rec/s)")
    }
}
