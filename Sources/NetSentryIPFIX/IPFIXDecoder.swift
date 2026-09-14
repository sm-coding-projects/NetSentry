import Foundation
import NetSentryCore

/// IPFIX (RFC 7011) message decoder with per-exporter session state. Not thread-safe by design:
/// one instance is owned by the decode stage. All input is untrusted; every read is bounds-checked
/// and every anomaly is reported as an `IPFIXEvent`.
public final class IPFIXDecoder {
    public struct Limits: Sendable {
        public var maxFieldsPerTemplate = 256
        public var maxTemplatesPerExporter = 1024
        public var maxPendingSetsPerExporter = 64
        public var maxPendingBytesPerExporter = 1 << 20
        public var pendingTTL: Duration = .seconds(300)
        public var templateLifetime: Duration = .seconds(1800)
        public var maxExporters = 64
        public var clockSkewWarning: Duration = .seconds(60)
        public init() {}
    }

    private struct PendingSet {
        let templateID: UInt16
        let bytes: Data
        let receivedAt: Timestamp
        let header: IPFIXMessageHeader
    }

    private final class Session {
        var state: IPFIXExporterState
        var pending: [UInt16: [PendingSet]] = [:]
        init(key: ExporterKey, now: Timestamp) { state = IPFIXExporterState(key: key, firstSeen: now, lastSeen: now) }
    }

    public let limits: Limits
    private var sessions: [ExporterKey: Session] = [:]
    private let normalizer = FlowNormalizer()

    public init(limits: Limits = Limits()) { self.limits = limits }

    public var exporters: [IPFIXExporterState] { sessions.values.map(\.state).sorted { $0.key.description < $1.key.description } }
    public func exporter(_ key: ExporterKey) -> IPFIXExporterState? { sessions[key]?.state }

    // MARK: - Entry point

    public func decode(_ datagram: RawDatagram) -> IPFIXDecodeResult {
        var result = IPFIXDecodeResult()
        var reader = ByteReader(datagram.payload)
        guard let version = reader.u16() else { result.events.append(.malformed("datagram shorter than 2 bytes")); return result }
        guard version == 10 else { result.events.append(.unsupportedVersion(version)); return result }
        guard let length = reader.u16(), let exportTime = reader.u32(), let seq = reader.u32(), let domain = reader.u32() else {
            result.events.append(.malformed("truncated message header")); return result
        }
        let header = IPFIXMessageHeader(version: version, length: length, exportTime: exportTime, sequenceNumber: seq, observationDomainID: domain)
        result.header = header
        if Int(length) < IPFIXMessageHeader.size { result.events.append(.malformed("message length \(length) < header")); return result }
        if Int(length) > datagram.payload.count { result.events.append(.malformed("message length \(length) exceeds datagram \(datagram.payload.count); decoding available bytes")) }
        let bodyEnd = min(Int(length), datagram.payload.count)

        let key = ExporterKey(address: datagram.source, observationDomain: domain)
        guard let session = session(for: key, now: datagram.receivedAt, events: &result.events) else {
            result.events.append(.malformed("exporter limit reached; ignoring \(key)")); return result
        }
        let st = session.state
        session.state.messages += 1
        session.state.lastSeen = datagram.receivedAt

        // Clock skew: exporter export time vs our receive time. Evaluated only once the message proved
        // well-formed (see end of decode), so garbage headers cannot poison the exporter's skew.
        let skew = Int64(exportTime) * 1_000_000 - datagram.receivedAt.microseconds

        expireTemplates(session, now: datagram.receivedAt, events: &result.events)
        expirePending(session, now: datagram.receivedAt, events: &result.events)

        var sets = ByteReader(datagram.payload, offset: IPFIXMessageHeader.size, end: bodyEnd)
        var dataRecords = 0
        var undecodableRecords = false
        while sets.remaining >= 4 {
            guard let setID = sets.u16(), let setLength = sets.u16() else { break }
            if setLength < 4 { result.events.append(.malformed("set \(setID) with length \(setLength)")); break }
            let bodyLength = Int(setLength) - 4
            guard let body = sets.slice(length: bodyLength) else {
                result.events.append(.malformed("set \(setID) length \(setLength) exceeds message")); break
            }
            _ = sets.skip(bodyLength)
            switch setID {
            case 2: decodeTemplateSet(body, kind: .data, session: session, now: datagram.receivedAt, events: &result.events)
            case 3: decodeTemplateSet(body, kind: .options, session: session, now: datagram.receivedAt, events: &result.events)
            case 0..<256: result.events.append(.malformed("reserved set id \(setID)"))
            default:
                if let template = session.state.templates[setID] {
                    session.state.templates[setID]?.lastRefreshed = datagram.receivedAt
                    let n = decodeDataSet(body, template: template, session: session, header: header, receivedAt: datagram.receivedAt,
                                          transportSource: datagram.source, result: &result)
                    dataRecords += n
                } else {
                    undecodableRecords = true
                    buffer(body, templateID: setID, session: session, header: header, receivedAt: datagram.receivedAt, events: &result.events)
                }
            }
        }
        if sets.remaining > 0 && sets.remaining < 4 { /* trailing padding; RFC allows */ }

        // Templates that arrived in this message may unlock buffered sets.
        drainPending(session, transportSource: datagram.source, result: &result)

        let wellFormed = !result.events.contains { if case .malformed = $0 { return true }; return false }
        if wellFormed, abs(skew) < 10 * 365 * 86_400 * 1_000_000 {
            let previous = st.clockSkewMicroseconds
            session.state.clockSkewMicroseconds = skew
            if abs(skew) > limits.clockSkewWarning.microsecondsValue, abs(previous ?? 0) <= limits.clockSkewWarning.microsecondsValue {
                result.events.append(.clockSkew(exporter: key, skewMicroseconds: skew))
            }
        }
        trackSequence(session, header: header, recordsInMessage: dataRecords, uncertain: undecodableRecords, events: &result.events)
        result.dataRecordCount = dataRecords
        session.state.records += UInt64(dataRecords)
        return result
    }

    /// Drops per-exporter state (used by tests and when the user removes an exporter).
    public func reset(exporter: ExporterKey) { sessions.removeValue(forKey: exporter) }

    /// Housekeeping to call periodically even when an exporter is silent.
    public func expire(now: Timestamp) -> [IPFIXEvent] {
        var events: [IPFIXEvent] = []
        for s in sessions.values {
            expireTemplates(s, now: now, events: &events)
            expirePending(s, now: now, events: &events)
        }
        return events
    }

    // MARK: - Sessions

    private func session(for key: ExporterKey, now: Timestamp, events: inout [IPFIXEvent]) -> Session? {
        if let s = sessions[key] { events.append(.exporterSeen(exporter: key, first: false)); return s }
        guard sessions.count < limits.maxExporters else { return nil }
        let s = Session(key: key, now: now)
        sessions[key] = s
        events.append(.exporterSeen(exporter: key, first: true))
        return s
    }

    // MARK: - Templates

    private func decodeTemplateSet(_ body: ByteReader, kind: TemplateKind, session: Session, now: Timestamp, events: inout [IPFIXEvent]) {
        var r = body
        let key = session.state.key
        while r.remaining >= 4 {
            guard let templateID = r.u16(), let fieldCount = r.u16() else { break }
            if templateID == 0 && fieldCount == 0 { break }   // padding
            var scopeCount = 0
            if kind == .options {
                guard let sc = r.u16() else { events.append(.malformed("truncated options template header")); return }
                scopeCount = Int(sc)
            }
            if templateID < 256 {
                events.append(.templateRejected(exporter: key, template: templateID, reason: "template id below 256"))
                return
            }
            if fieldCount == 0 {
                // Template withdrawal (RFC 7011 §8.1).
                if session.state.templates.removeValue(forKey: templateID) != nil { events.append(.templateWithdrawn(exporter: key, template: templateID)) }
                continue
            }
            if Int(fieldCount) > limits.maxFieldsPerTemplate {
                events.append(.templateRejected(exporter: key, template: templateID, reason: "\(fieldCount) fields exceeds limit"))
                return
            }
            if kind == .options && (scopeCount == 0 || scopeCount > Int(fieldCount)) {
                events.append(.templateRejected(exporter: key, template: templateID, reason: "invalid scope count \(scopeCount)"))
                return
            }
            var fields: [TemplateField] = []
            fields.reserveCapacity(Int(fieldCount))
            for _ in 0..<fieldCount {
                guard let rawID = r.u16(), let length = r.u16() else { events.append(.malformed("truncated template \(templateID)")); return }
                var pen: UInt32 = 0
                if rawID & 0x8000 != 0 {
                    guard let p = r.u32() else { events.append(.malformed("truncated enterprise number in template \(templateID)")); return }
                    pen = p
                }
                fields.append(TemplateField(elementID: rawID & 0x7FFF, enterpriseNumber: pen, length: length))
            }
            let template = IPFIXTemplate(id: templateID, kind: kind, scopeFieldCount: scopeCount, fields: fields, receivedAt: now)
            if template.minimumRecordLength == 0 {
                events.append(.templateRejected(exporter: key, template: templateID, reason: "zero-length record"))
                continue
            }
            if let existing = session.state.templates[templateID] {
                if existing.isEquivalent(to: template) {
                    session.state.templates[templateID]?.lastRefreshed = now
                    session.state.templates[templateID]?.refreshCount += 1
                    events.append(.templateRefreshed(exporter: key, template: templateID))
                } else {
                    session.state.templates[templateID] = template
                    events.append(.templateReplaced(exporter: key, template: templateID, fieldCount: fields.count))
                }
            } else {
                guard session.state.templates.count < limits.maxTemplatesPerExporter else {
                    events.append(.templateRejected(exporter: key, template: templateID, reason: "template limit reached")); return
                }
                session.state.templates[templateID] = template
                events.append(.templateAdded(exporter: key, template: templateID, kind: kind, fieldCount: fields.count))
            }
        }
    }

    private func expireTemplates(_ session: Session, now: Timestamp, events: inout [IPFIXEvent]) {
        let lifetime = limits.templateLifetime.microsecondsValue
        for (id, t) in session.state.templates where now.microseconds - t.lastRefreshed.microseconds > lifetime {
            session.state.templates.removeValue(forKey: id)
            events.append(.templateExpired(exporter: session.state.key, template: id))
        }
    }

    // MARK: - Pending (data before template)

    private func buffer(_ body: ByteReader, templateID: UInt16, session: Session, header: IPFIXMessageHeader, receivedAt: Timestamp, events: inout [IPFIXEvent]) {
        let key = session.state.key
        let bytes = body.data.subdata(in: body.offset..<body.end)
        let canBuffer = session.state.pendingSets < limits.maxPendingSetsPerExporter && session.state.pendingBytes + bytes.count <= limits.maxPendingBytesPerExporter
        events.append(.missingTemplate(exporter: key, template: templateID, bytes: bytes.count, buffered: canBuffer))
        guard canBuffer else { return }
        session.pending[templateID, default: []].append(PendingSet(templateID: templateID, bytes: bytes, receivedAt: receivedAt, header: header))
        session.state.pendingSets += 1
        session.state.pendingBytes += bytes.count
    }

    private func drainPending(_ session: Session, transportSource: IPAddress, result: inout IPFIXDecodeResult) {
        for (templateID, sets) in session.pending {
            guard let template = session.state.templates[templateID] else { continue }
            var records = 0
            for p in sets {
                records += decodeDataSet(ByteReader(p.bytes), template: template, session: session, header: p.header, receivedAt: p.receivedAt,
                                         transportSource: transportSource, result: &result)
                session.state.pendingSets -= 1
                session.state.pendingBytes -= p.bytes.count
            }
            session.pending.removeValue(forKey: templateID)
            result.events.append(.pendingDecoded(exporter: session.state.key, template: templateID, records: records))
        }
    }

    private func expirePending(_ session: Session, now: Timestamp, events: inout [IPFIXEvent]) {
        let ttl = limits.pendingTTL.microsecondsValue
        for (templateID, sets) in session.pending {
            let stale = sets.filter { now.microseconds - $0.receivedAt.microseconds > ttl }
            guard !stale.isEmpty else { continue }
            let keep = sets.filter { now.microseconds - $0.receivedAt.microseconds <= ttl }
            session.state.pendingSets -= stale.count
            session.state.pendingBytes -= stale.reduce(0) { $0 + $1.bytes.count }
            if keep.isEmpty { session.pending.removeValue(forKey: templateID) } else { session.pending[templateID] = keep }
            events.append(.pendingDropped(exporter: session.state.key, template: templateID, sets: stale.count, reason: "template never arrived"))
        }
    }

    // MARK: - Data records

    /// Returns the number of records decoded from the set.
    private func decodeDataSet(_ body: ByteReader, template: IPFIXTemplate, session: Session, header: IPFIXMessageHeader, receivedAt: Timestamp,
                               transportSource: IPAddress, result: inout IPFIXDecodeResult) -> Int {
        var r = body
        var count = 0
        let minLen = template.minimumRecordLength
        while r.remaining >= minLen {
            var fields: [DecodedField] = []
            fields.reserveCapacity(template.fields.count)
            var ok = true
            for f in template.fields {
                var len = Int(f.length)
                if f.isVariableLength {
                    guard let l1 = r.u8() else { ok = false; break }
                    if l1 == 255 {
                        guard let l2 = r.u16() else { ok = false; break }
                        len = Int(l2)
                    } else { len = Int(l1) }
                }
                guard let bytes = r.bytes(len) else { ok = false; break }
                fields.append(DecodedField(field: f, bytes: bytes))
            }
            guard ok else {
                result.events.append(.malformed("truncated record for template \(template.id) after \(count) records"))
                return count
            }
            count += 1
            switch template.kind {
            case .options:
                let scope = Array(fields.prefix(template.scopeFieldCount))
                let values = Array(fields.dropFirst(template.scopeFieldCount))
                let rec = IPFIXOptionsRecord(exporter: session.state.key, templateID: template.id, receivedAt: receivedAt, scope: scope, values: values)
                result.options.append(rec)
                absorbOptions(rec, session: session, events: &result.events)
            case .data:
                let flow = normalizer.normalize(fields: fields, header: header, receivedAt: receivedAt, exporter: session.state.key, state: session.state)
                result.flows.append(flow)
            }
        }
        return count
    }

    /// Learns sampling, interface names, domain names and restarts from options records.
    private func absorbOptions(_ rec: IPFIXOptionsRecord, session: Session, events: inout [IPFIXEvent]) {
        let key = session.state.key
        var sampling = SamplingInfo()
        var sawSampling = false
        for f in rec.scope + rec.values where f.field.enterpriseNumber == 0 {
            switch f.field.elementID {
            case 302: sampling.selectorID = f.unsigned
            case 390, 304: sampling.algorithm = f.unsigned.map { UInt16(truncatingIfNeeded: $0) }; sawSampling = true
            case 309: sampling.size = f.unsigned.map { UInt32(truncatingIfNeeded: $0) }; sawSampling = true
            case 310: sampling.population = f.unsigned.map { UInt32(truncatingIfNeeded: $0) }; sawSampling = true
            case 305: sampling.packetInterval = f.unsigned.map { UInt32(truncatingIfNeeded: $0) }; sawSampling = true
            case 306: sampling.packetSpace = f.unsigned.map { UInt32(truncatingIfNeeded: $0) }; sawSampling = true
            case 34: sampling.legacyInterval = f.unsigned.map { UInt32(truncatingIfNeeded: $0) }; sawSampling = true
            case 300: if let n = f.string, !n.isEmpty, session.state.observationDomainName != n {
                session.state.observationDomainName = n; events.append(.observationDomainName(exporter: key, name: n)) }
            case 160:
                if let v = f.unsigned, let t = FlowNormalizer.plausible(milliseconds: v) {
                    if let old = session.state.systemInitTime, old != t {
                        session.state.restarts += 1
                        events.append(.exporterRestart(exporter: key, reason: "systemInitTimeMilliseconds changed"))
                    }
                    session.state.systemInitTime = t
                }
            default: break
            }
        }
        if sawSampling, sampling.rate != nil {
            if let sel = sampling.selectorID { session.state.sampling[sel] = sampling } else { session.state.defaultSampling = sampling }
            events.append(.samplingLearned(exporter: key, info: sampling))
        }
        if let ifIndex = rec.value(10)?.unsigned ?? rec.value(252)?.unsigned, let name = rec.value(82)?.string, !name.isEmpty {
            let idx = UInt32(truncatingIfNeeded: ifIndex)
            if session.state.interfaceNames[idx] != name {
                session.state.interfaceNames[idx] = name
                events.append(.interfaceName(exporter: key, index: idx, name: name, description: rec.value(83)?.string))
            }
        }
    }

    // MARK: - Sequence tracking (RFC 7011 §3.1: sequence counts data records)

    private func trackSequence(_ session: Session, header: IPFIXMessageHeader, recordsInMessage: Int, uncertain: Bool, events: inout [IPFIXEvent]) {
        let key = session.state.key
        let seq = header.sequenceNumber
        if let expected = session.state.expectedSequence, expected != seq {
            let delta = Int64(seq) - Int64(expected)
            if delta < -1_000_000 || (delta < 0 && seq < 1_000) {
                session.state.restarts += 1
                events.append(.exporterRestart(exporter: key, reason: "sequence reset from \(expected) to \(seq)"))
            } else if delta > 0 {
                session.state.sequenceGaps += 1
                events.append(.sequenceGap(exporter: key, expected: expected, received: seq, missingRecords: delta))
            } else {
                // Negative small delta: reordered or duplicated datagram; report as a gap of negative size.
                events.append(.sequenceGap(exporter: key, expected: expected, received: seq, missingRecords: delta))
            }
        }
        session.state.lastSequence = seq
        // When some sets could not be decoded we cannot know how many records they held.
        session.state.expectedSequence = uncertain ? nil : seq &+ UInt32(recordsInMessage)
    }
}
