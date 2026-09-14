import Foundation
import NetSentryCore
import NetSentryIPFIX
import NetSentrySyslog
import os

/// Output of decoding one receive batch.
struct DecodedBatch: Sendable {
    var flows: [FlowRecord] = []
    var events: [SyslogEvent] = []
    var ipfixEvents: [IPFIXEvent] = []
    var unparsedEvents = 0
    var templatesSeen = 0
    var raw: [RawDatagram] = []
}

/// Owns the IPFIX decoder and syslog parser. Single consumer; runs off the receive queue.
actor DecodeStage {
    private let log = Log.logger("decode", process: "collector")
    private let ipfix = IPFIXDecoder()
    private var syslog: SyslogParser
    private var lastExpiry = Timestamp.now

    init(timeZone: TimeZone = .current) {
        syslog = SyslogParser(timeZone: timeZone)
    }

    func decode(_ batch: [RawDatagram]) -> DecodedBatch {
        var out = DecodedBatch()
        for d in batch {
            switch d.kind {
            case .ipfix:
                let r = ipfix.decode(d)
                out.flows.append(contentsOf: r.flows)
                out.ipfixEvents.append(contentsOf: r.events)
                for e in r.events { if case .templateAdded = e { out.templatesSeen += 1 } }
            case .syslog:
                let e = syslog.parse(d)
                if e.parseStatus == .unparsed { out.unparsedEvents += 1 }
                out.events.append(e)
            }
        }
        // Periodic housekeeping for silent exporters.
        let now = Timestamp.now
        if now.microseconds - lastExpiry.microseconds > 30_000_000 {
            lastExpiry = now
            out.ipfixEvents.append(contentsOf: ipfix.expire(now: now))
        }
        return out
    }

    var exporterStates: [IPFIXExporterState] { ipfix.exporters }
}

/// Minimal Phase 2 enrichment: direction and internal/external classification from configured networks.
/// Client identity, GeoIP/ASN and service names arrive in Phase 5.
struct DirectionClassifier: Sendable {
    let internalPrefixes: [IPPrefix]

    func isInternal(_ ip: IPAddress) -> Bool { ip.isPrivate || ip.isLinkLocal || ip.isLoopback || internalPrefixes.contains { $0.contains(ip) } }

    func classify(_ f: inout FlowRecord) {
        let s = isInternal(f.srcIP), d = isInternal(f.dstIP)
        f.enrichment.srcInternal = s
        f.enrichment.dstInternal = d
        f.enrichment.direction = switch (s, d) {
        case (true, true): f.dstIP.isMulticast ? .lan : .lan
        case (true, false): .outbound
        case (false, true): .inbound
        case (false, false): .transit
        }
        f.enrichment.enrichmentVersion = 1
    }

    func classify(_ e: inout SyslogEvent) {
        guard let src = e.srcIP, let dst = e.dstIP else { return }
        let s = isInternal(src), d = isInternal(dst)
        e.enrichment.srcInternal = s
        e.enrichment.dstInternal = d
        e.enrichment.direction = switch (s, d) {
        case (true, true): .lan
        case (true, false): .outbound
        case (false, true): .inbound
        case (false, false): .transit
        }
        e.enrichment.enrichmentVersion = 1
    }
}
