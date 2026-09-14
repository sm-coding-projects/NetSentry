import Foundation
import NetSentryCore

/// Maps decoded IPFIX fields onto the normalized `FlowRecord`. Anything not mapped is preserved in
/// `extraElements` with its enterprise number and element id.
struct FlowNormalizer {
    private static let ntpEpochOffset: Int64 = 2_208_988_800   // seconds between 1900 and 1970

    func normalize(fields: [DecodedField], header: IPFIXMessageHeader, receivedAt: Timestamp, exporter: ExporterKey, state: IPFIXExporterState) -> FlowRecord {
        let exportTime = Timestamp(seconds: Int64(header.exportTime))
        var flow = FlowRecord(exporter: exporter, exportSequence: header.sequenceNumber, receivedAt: receivedAt, exportTime: exportTime,
                              startTime: exportTime, endTime: exportTime, srcIP: IPAddress(v4: 0), dstIP: IPAddress(v4: 0))
        flow.clockSkewMicroseconds = state.clockSkewMicroseconds ?? 0
        var start: Timestamp?, end: Timestamp?
        var startSysUp: UInt64?, endSysUp: UInt64?
        var selector: UInt64?
        var sawV6 = false

        for f in fields {
            let id = f.field.elementID
            if f.field.isReverse {
                switch id {
                case 1: flow.reverseOctets = f.unsigned
                case 2: flow.reversePackets = f.unsigned
                default: flow.extraElements.append(RawInformationElement(enterpriseNumber: f.field.enterpriseNumber, elementID: id, value: f.bytes))
                }
                continue
            }
            if f.field.enterpriseNumber != 0 {
                flow.extraElements.append(RawInformationElement(enterpriseNumber: f.field.enterpriseNumber, elementID: id, value: f.bytes))
                continue
            }
            switch id {
            case 1: flow.octets = f.unsigned ?? 0
            case 2: flow.packets = f.unsigned ?? 0
            case 85: if flow.octets == 0 { flow.octets = f.unsigned ?? 0 }
            case 86: if flow.packets == 0 { flow.packets = f.unsigned ?? 0 }
            case 4: flow.protocolNumber = UInt8(truncatingIfNeeded: f.unsigned ?? 0)
            case 6: flow.tcpFlags = UInt16(truncatingIfNeeded: f.unsigned ?? 0)
            case 7, 180, 182: flow.srcPort = UInt16(truncatingIfNeeded: f.unsigned ?? 0)
            case 11, 181, 183: flow.dstPort = UInt16(truncatingIfNeeded: f.unsigned ?? 0)
            case 8: if let ip = f.ipAddress, !sawV6 { flow.srcIP = ip }
            case 12: if let ip = f.ipAddress, !sawV6 { flow.dstIP = ip }
            case 27: if let ip = f.ipAddress, ip.version == 6 { flow.srcIP = ip; sawV6 = true }
            case 28: if let ip = f.ipAddress, ip.version == 6 { flow.dstIP = ip; sawV6 = true }
            case 10: flow.ingressInterface = f.unsigned.map { UInt32(truncatingIfNeeded: $0) }
            case 14: flow.egressInterface = f.unsigned.map { UInt32(truncatingIfNeeded: $0) }
            case 58: flow.srcVLAN = f.unsigned.map { UInt16(truncatingIfNeeded: $0) }
            case 59: flow.dstVLAN = f.unsigned.map { UInt16(truncatingIfNeeded: $0) }
            case 243: if flow.srcVLAN == nil { flow.srcVLAN = f.unsigned.map { UInt16(truncatingIfNeeded: $0) } }
            case 254: if flow.dstVLAN == nil { flow.dstVLAN = f.unsigned.map { UInt16(truncatingIfNeeded: $0) } }
            case 61: flow.flowDirection = f.unsigned.map { UInt8(truncatingIfNeeded: $0) }
            case 136: flow.flowEndReason = f.unsigned.map { UInt8(truncatingIfNeeded: $0) }
            case 32, 139:
                if let v = f.unsigned { flow.icmpType = UInt8(truncatingIfNeeded: v >> 8); flow.icmpCode = UInt8(truncatingIfNeeded: v & 0xff) }
            case 176, 178: flow.icmpType = f.unsigned.map { UInt8(truncatingIfNeeded: $0) }
            case 177, 179: flow.icmpCode = f.unsigned.map { UInt8(truncatingIfNeeded: $0) }
            case 150: start = f.unsigned.flatMap { Self.plausible(seconds: $0) }
            case 151: end = f.unsigned.flatMap { Self.plausible(seconds: $0) }
            case 152: start = f.unsigned.flatMap { Self.plausible(milliseconds: $0) }
            case 153: end = f.unsigned.flatMap { Self.plausible(milliseconds: $0) }
            case 154: start = Self.ntp(f.bytes)
            case 155: end = Self.ntp(f.bytes)
            case 156: start = Self.ntp(f.bytes)
            case 157: end = Self.ntp(f.bytes)
            case 158: start = f.unsigned.map { Timestamp(microseconds: exportTime.microseconds - Int64(clamping: $0)) }
            case 159: end = f.unsigned.map { Timestamp(microseconds: exportTime.microseconds - Int64(clamping: $0)) }
            case 22: startSysUp = f.unsigned
            case 21: endSysUp = f.unsigned
            case 34: flow.samplingInterval = f.unsigned.map { UInt32(truncatingIfNeeded: $0) }
            case 302: selector = f.unsigned
            case 225: flow.postNATSrcIP = f.ipAddress
            case 226: flow.postNATDstIP = f.ipAddress
            case 281: flow.postNATSrcIP = f.ipAddress
            case 282: flow.postNATDstIP = f.ipAddress
            case 227: flow.postNATSrcPort = f.unsigned.map { UInt16(truncatingIfNeeded: $0) }
            case 228: flow.postNATDstPort = f.unsigned.map { UInt16(truncatingIfNeeded: $0) }
            case 95: flow.applicationID = f.bytes.map { String(format: "%02x", $0) }.joined()
            case 96: flow.applicationID = f.string ?? flow.applicationID
            case 60: break   // ipVersion is implied by the address fields
            default:
                flow.extraElements.append(RawInformationElement(enterpriseNumber: 0, elementID: id, value: f.bytes))
            }
        }

        // Timestamps: absolute > sysUpTime relative to systemInitTime > export time.
        if start == nil, let s = startSysUp, s < UInt64(UInt32.max), let base = state.systemInitTime { start = Timestamp(microseconds: base.microseconds + Int64(s) * 1000) }
        if end == nil, let e = endSysUp, e < UInt64(UInt32.max), let base = state.systemInitTime { end = Timestamp(microseconds: base.microseconds + Int64(e) * 1000) }
        flow.startTime = start ?? end ?? exportTime
        flow.endTime = end ?? start ?? exportTime
        if flow.endTime < flow.startTime { flow.endTime = flow.startTime }

        // Sampling: per-selector info from options templates, else exporter default, else IE 34.
        if flow.samplingInterval == nil {
            if let sel = selector, let info = state.sampling[sel] { flow.samplingInterval = info.rate }
            else if let info = state.defaultSampling { flow.samplingInterval = info.rate }
        }
        return flow
    }

    static let maxPlausibleSeconds: UInt64 = 7_258_118_400   // year 2200; anything beyond is corrupt input

    static func plausible(seconds v: UInt64) -> Timestamp? { v <= maxPlausibleSeconds ? Timestamp(seconds: Int64(v)) : nil }
    static func plausible(milliseconds v: UInt64) -> Timestamp? { v <= maxPlausibleSeconds * 1_000 ? Timestamp(milliseconds: Int64(v)) : nil }

    /// NTP 64-bit timestamp: 32-bit seconds since 1900 + 32-bit fraction.
    private static func ntp(_ bytes: Data) -> Timestamp? {
        guard bytes.count == 8 else { return nil }
        let secs = bytes.prefix(4).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let frac = bytes.suffix(4).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let micro = (frac * 1_000_000) >> 32
        return Timestamp(microseconds: (Int64(secs) - ntpEpochOffset) * 1_000_000 + Int64(micro))
    }
}
