import Foundation
import NetSentryCore

/// Builds valid (and deliberately malformed) IPFIX v10 datagrams for tests and `nsgen`.
public struct IPFIXBuilder: Sendable {
    public struct Field: Sendable { public let id: UInt16; public let pen: UInt32; public let length: UInt16
        public init(_ id: UInt16, _ length: UInt16, pen: UInt32 = 0) { self.id = id; self.pen = pen; self.length = length } }

    public var observationDomain: UInt32
    public var sequence: UInt32
    public var exportTime: UInt32
    private var sets: [Data] = []

    public init(observationDomain: UInt32 = 1, sequence: UInt32 = 0, exportTime: UInt32 = UInt32(Date().timeIntervalSince1970)) {
        self.observationDomain = observationDomain; self.sequence = sequence; self.exportTime = exportTime
    }

    /// The field list the UCG Fiber exports for IPv4 flows (observed 2026-09-10, template 264).
    public static let ucgFiberV4Fields: [Field] = [
        .init(8, 4), .init(12, 4), .init(15, 4), .init(60, 1), .init(7, 2), .init(11, 2), .init(6, 1), .init(10, 2), .init(14, 2),
        .init(2, 4), .init(1, 4), .init(152, 8), .init(153, 8), .init(4, 1), .init(5, 1), .init(136, 1), .init(80, 6), .init(56, 6),
        .init(256, 2), .init(61, 1), .init(302, 1),
    ]
    public static let ipv6Fields: [Field] = [
        .init(27, 16), .init(28, 16), .init(7, 2), .init(11, 2), .init(4, 1), .init(6, 2), .init(2, 8), .init(1, 8), .init(152, 8), .init(153, 8),
    ]

    public mutating func addTemplate(id: UInt16, fields: [Field]) { sets.append(Self.templateSet(setID: 2, id: id, scope: nil, fields: fields)) }
    public mutating func addOptionsTemplate(id: UInt16, scopeCount: UInt16, fields: [Field]) { sets.append(Self.templateSet(setID: 3, id: id, scope: scopeCount, fields: fields)) }
    public mutating func addWithdrawal(id: UInt16) { var d = Data(); d.append(be16(2)); d.append(be16(8)); d.append(be16(id)); d.append(be16(0)); sets.append(d) }

    /// Adds a data set; each record is pre-encoded bytes (use `encode(fields:values:)`).
    public mutating func addDataSet(templateID: UInt16, records: [Data], padding: Int = 0) {
        var d = Data()
        let body = records.reduce(Data()) { $0 + $1 } + Data(count: padding)
        d.append(be16(templateID)); d.append(be16(UInt16(4 + body.count))); d.append(body)
        sets.append(d)
    }

    public mutating func addRawSet(_ data: Data) { sets.append(data) }

    /// Serializes the message and advances the sequence by `dataRecords`.
    public mutating func build(dataRecords: Int, lengthOverride: UInt16? = nil, version: UInt16 = 10) -> Data {
        var body = Data()
        for s in sets { body.append(s) }
        var d = Data()
        d.append(be16(version)); d.append(be16(lengthOverride ?? UInt16(16 + body.count)))
        d.append(be32(exportTime)); d.append(be32(sequence)); d.append(be32(observationDomain))
        d.append(body)
        sets.removeAll()
        sequence &+= UInt32(dataRecords)
        return d
    }

    // MARK: Encoding helpers

    /// Encodes one record from a list of values in template order. Values: UInt64 numbers, IPAddress, Data, String.
    public static func encode(fields: [Field], values: [any Sendable]) -> Data {
        precondition(fields.count == values.count)
        var d = Data()
        for (f, v) in zip(fields, values) {
            let bytes: Data
            switch v {
            case let n as UInt64: bytes = beN(n, count: Int(f.length == 65535 ? 8 : f.length))
            case let n as Int: bytes = beN(UInt64(n), count: Int(f.length == 65535 ? 8 : f.length))
            case let ip as IPAddress: bytes = Data(ip.bytes)
            case let s as String: bytes = Data(s.utf8)
            case let raw as Data: bytes = raw
            default: bytes = Data()
            }
            if f.length == 65535 {
                if bytes.count < 255 { d.append(UInt8(bytes.count)) } else { d.append(255); d.append(be16(UInt16(bytes.count))) }
                d.append(bytes)
            } else {
                var b = bytes
                let padRight = v is String || v is Data   // strings/octets are NUL-padded on the right; numbers on the left
                if b.count < Int(f.length) { b = padRight ? b + Data(count: Int(f.length) - b.count) : Data(count: Int(f.length) - b.count) + b }
                d.append(padRight ? b.prefix(Int(f.length)) : b.suffix(Int(f.length)))
            }
        }
        return d
    }

    private static func templateSet(setID: UInt16, id: UInt16, scope: UInt16?, fields: [Field]) -> Data {
        var body = Data()
        body.append(be16(id)); body.append(be16(UInt16(fields.count)))
        if let scope { body.append(be16(scope)) }
        for f in fields {
            if f.pen != 0 { body.append(be16(f.id | 0x8000)); body.append(be16(f.length)); body.append(be32(f.pen)) }
            else { body.append(be16(f.id)); body.append(be16(f.length)) }
        }
        var d = Data(); d.append(be16(setID)); d.append(be16(UInt16(4 + body.count))); d.append(body)
        return d
    }

    static func beN(_ v: UInt64, count: Int) -> Data { Data((0..<count).map { UInt8(truncatingIfNeeded: v >> (8 * UInt64(count - 1 - $0))) }) }
}

private func be16(_ v: UInt16) -> Data { Data([UInt8(v >> 8), UInt8(v & 0xff)]) }
private func be32(_ v: UInt32) -> Data { Data([UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]) }

/// Deterministic flow generator producing records shaped like the UCG Fiber's IPv4 template.
public struct SyntheticFlowSource {
    public var rng: SplitMix64
    public let clients: [IPAddress]
    public let destinations: [IPAddress]
    public init(seed: UInt64 = 42, clientCount: Int = 40, destinationCount: Int = 200) {
        rng = SplitMix64(seed: seed)
        clients = (0..<clientCount).map { IPAddress(v4: 0xC0A8_6300 | UInt32(10 + $0)) }             // 192.168.99.10+
        var r = SplitMix64(seed: seed ^ 0xABCDEF)
        destinations = (0..<destinationCount).map { _ in IPAddress(v4: 0xCB00_7100 | UInt32(r.next() % 200) | (UInt32(r.next() % 4) << 8)) } // 203.0.113.x / 203.0.114.x
    }

    /// One record for the UCG-shaped template. `time` is flow end in milliseconds.
    public mutating func nextRecord(endMilliseconds: UInt64) -> Data {
        let outbound = rng.next() % 4 != 0
        let c = clients[Int(rng.next() % UInt64(clients.count))]
        let d = destinations[Int(rng.next() % UInt64(destinations.count))]
        let proto: UInt64 = rng.next() % 10 == 0 ? 17 : 6
        let dport: UInt64 = [443, 443, 443, 80, 53, 853, 22, 8443, 123][Int(rng.next() % 9)]
        let pkts = 1 + rng.next() % 50, octets = pkts * (60 + rng.next() % 1400)
        let dur = rng.next() % 30_000
        let values: [any Sendable] = [
            outbound ? c : d, outbound ? d : c, IPAddress(v4: 0xC0A8_6301), UInt64(4),
            outbound ? 40000 + rng.next() % 20000 : dport, outbound ? dport : 40000 + rng.next() % 20000,
            UInt64(0x1b), UInt64(outbound ? 5 : 3), UInt64(outbound ? 3 : 5), pkts, octets,
            endMilliseconds - dur, endMilliseconds, proto, UInt64(0), UInt64(rng.next() % 3 + 1),
            // L2 addresses as the gateway's ingress interface sees them: the client's MAC is stable per client
            // address; the other side is the gateway's own interface MAC.
            outbound ? Self.gatewayMAC : Self.clientMAC(c), outbound ? Self.clientMAC(c) : Self.gatewayMAC,
            UInt64(0x0800), UInt64(outbound ? 1 : 0), UInt64(3),
        ]
        return IPFIXBuilder.encode(fields: IPFIXBuilder.ucgFiberV4Fields, values: values)
    }
}

extension SyntheticFlowSource {
    static let gatewayMAC = Data([0x24, 0x5a, 0x4c, 0x11, 0x22, 0x33])
    /// Deterministic per client address (last two IPv4 octets), so identity resolution sees a stable device.
    static func clientMAC(_ ip: IPAddress) -> Data {
        let b = Array(ip.bytes.suffix(2))
        return Data([0x00, 0x11, 0x22, 0x33, b.count > 1 ? b[0] : 0, b.last ?? 0])
    }
}

public struct SplitMix64: Sendable {
    private var state: UInt64
    public init(seed: UInt64) { state = seed }
    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
