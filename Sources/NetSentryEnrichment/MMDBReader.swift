import Foundation
import NetSentryCore

/// Reader for the MaxMind DB format (https://maxmind.github.io/MaxMind-DB/) used by GeoLite2 and DB-IP
/// databases. Pure Swift, memory-mapped, no external dependency. Only the fields NetSentry uses are
/// extracted (country ISO code, ASN, organization) but the decoder handles every MMDB data type.
public final class MMDBReader: @unchecked Sendable {
    public struct Metadata: Sendable {
        public var nodeCount: UInt32
        public var recordSize: UInt16
        public var ipVersion: UInt16
        public var databaseType: String
        public var buildEpoch: UInt64
        public var languages: [String]
        public var description: [String: String]
    }

    public enum Value: Sendable, Equatable {
        case string(String), double(Double), bytes(Data), uint16(UInt16), uint32(UInt32), uint64(UInt64), uint128(Data), int32(Int32)
        case map([String: Value]), array([Value]), bool(Bool), float(Float), null
        public subscript(key: String) -> Value? { if case .map(let m) = self { return m[key] }; return nil }
        public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
        public var uintValue: UInt64? {
            switch self { case .uint16(let v): UInt64(v); case .uint32(let v): UInt64(v); case .uint64(let v): v; case .int32(let v): v >= 0 ? UInt64(v) : nil; default: nil }
        }
    }

    public enum ReaderError: Error, LocalizedError {
        case metadataNotFound, unsupportedRecordSize(UInt16), corrupt(String)
        public var errorDescription: String? {
            switch self { case .metadataNotFound: "Not a MaxMind DB file"; case .unsupportedRecordSize(let s): "Unsupported record size \(s)"; case .corrupt(let m): "Corrupt database: \(m)" }
        }
    }

    private let data: Data
    public let metadata: Metadata
    private let searchTreeSize: Int
    private let dataSectionStart: Int
    private let ipv4Start: UInt32

    private static let metadataMarker = Data([0xAB, 0xCD, 0xEF]) + Data("MaxMind.com".utf8)
    private static let dataSeparator = 16

    public convenience init(path: String) throws {
        try self.init(data: try Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe))
        _ = metadata
    }

    public init(data: Data) throws {
        self.data = data
        // Metadata lives after the last occurrence of the marker (within the final 128 KiB).
        let tail = max(0, data.count - 131_072)
        guard let markerRange = data.range(of: Self.metadataMarker, options: .backwards, in: tail..<data.count) else { throw ReaderError.metadataNotFound }
        var d = Decoder(data: data, dataStart: markerRange.upperBound)
        let meta = try d.decode(at: markerRange.upperBound).value
        guard case .map(let m) = meta else { throw ReaderError.corrupt("metadata is not a map") }
        let nodeCount = UInt32(m["node_count"]?.uintValue ?? 0)
        let recordSize = UInt16(m["record_size"]?.uintValue ?? 0)
        guard [24, 28, 32].contains(recordSize) else { throw ReaderError.unsupportedRecordSize(recordSize) }
        var langs: [String] = []
        if case .array(let a)? = m["languages"] { langs = a.compactMap(\.stringValue) }
        var desc: [String: String] = [:]
        if case .map(let dm)? = m["description"] { for (k, v) in dm { if let s = v.stringValue { desc[k] = s } } }
        metadata = Metadata(nodeCount: nodeCount, recordSize: recordSize, ipVersion: UInt16(m["ip_version"]?.uintValue ?? 6), databaseType: m["database_type"]?.stringValue ?? "",
                            buildEpoch: m["build_epoch"]?.uintValue ?? 0, languages: langs, description: desc)
        searchTreeSize = Int(nodeCount) * Int(recordSize) / 4
        dataSectionStart = searchTreeSize + Self.dataSeparator
        guard dataSectionStart <= data.count else { throw ReaderError.corrupt("search tree exceeds file") }
        // For IPv6 trees, IPv4 addresses live under ::/96: walk 96 zero bits once.
        var node: UInt32 = 0
        if metadata.ipVersion == 6 {
            for _ in 0..<96 { guard node < nodeCount else { break }; node = Self.readRecord(data: data, recordSize: recordSize, node: node, bit: 0) }
        }
        ipv4Start = node
    }

    // MARK: - Lookup

    /// Looks up an address; returns the decoded data map (nil when the address is not in the database).
    public func lookup(_ ip: IPAddress) -> Value? {
        let bytes = ip.bytes
        var node: UInt32
        let bits: Int
        if ip.version == 4 {
            if metadata.ipVersion == 4 { node = 0 } else { node = ipv4Start }
            bits = 32
        } else {
            guard metadata.ipVersion == 6 else { return nil }
            node = 0
            bits = 128
        }
        let nodeCount = metadata.nodeCount
        for i in 0..<bits {
            if node >= nodeCount { break }
            let bit = (bytes[i / 8] >> (7 - UInt8(i % 8))) & 1
            node = readRecord(node: node, bit: bit)
        }
        if node == nodeCount { return nil }                      // not found
        guard node > nodeCount else { return nil }
        let offset = Int(node - nodeCount) - Self.dataSeparator + dataSectionStart
        guard offset >= dataSectionStart, offset < data.count else { return nil }
        var d = Decoder(data: data, dataStart: dataSectionStart)
        return try? d.decode(at: offset).value
    }

    private func readRecord(node: UInt32, bit: UInt8) -> UInt32 { Self.readRecord(data: data, recordSize: metadata.recordSize, node: node, bit: bit) }

    private static func readRecord(data: Data, recordSize: UInt16, node: UInt32, bit: UInt8) -> UInt32 {
        let base = Int(node) * Int(recordSize) / 4
        switch recordSize {
        case 24:
            let o = base + (bit == 0 ? 0 : 3)
            return UInt32(data[o]) << 16 | UInt32(data[o + 1]) << 8 | UInt32(data[o + 2])
        case 28:
            if bit == 0 {
                return UInt32(data[base + 3] >> 4) << 24 | UInt32(data[base]) << 16 | UInt32(data[base + 1]) << 8 | UInt32(data[base + 2])
            }
            return UInt32(data[base + 3] & 0x0F) << 24 | UInt32(data[base + 4]) << 16 | UInt32(data[base + 5]) << 8 | UInt32(data[base + 6])
        default:
            let o = base + (bit == 0 ? 0 : 4)
            return UInt32(data[o]) << 24 | UInt32(data[o + 1]) << 16 | UInt32(data[o + 2]) << 8 | UInt32(data[o + 3])
        }
    }

    // MARK: - Convenience extractors

    public struct GeoResult: Sendable, Hashable {
        public var countryISO: String?
        public var asn: UInt32?
        public var organization: String?
    }

    /// Country (GeoLite2-Country/City, DB-IP) and/or ASN fields from one lookup.
    public func geo(_ ip: IPAddress) -> GeoResult {
        guard let v = lookup(ip) else { return GeoResult() }
        var r = GeoResult()
        r.countryISO = v["country"]?["iso_code"]?.stringValue ?? v["registered_country"]?["iso_code"]?.stringValue
        r.asn = v["autonomous_system_number"]?.uintValue.map { UInt32(truncatingIfNeeded: $0) }
        r.organization = v["autonomous_system_organization"]?.stringValue
        return r
    }

    // MARK: - Data section decoder

    struct Decoder {
        let data: Data
        let dataStart: Int
        private var depth = 0

        init(data: Data, dataStart: Int) { self.data = data; self.dataStart = dataStart }

        mutating func decode(at offset: Int) throws -> (value: Value, next: Int) {
            guard offset < data.count else { throw ReaderError.corrupt("offset beyond data") }
            depth += 1; defer { depth -= 1 }
            guard depth < 64 else { throw ReaderError.corrupt("nesting too deep") }
            let ctrl = data[offset]
            var type = Int(ctrl >> 5)
            var pos = offset + 1
            if type == 0 {                       // extended type
                guard pos < data.count else { throw ReaderError.corrupt("truncated extended type") }
                type = Int(data[pos]) + 7; pos += 1
            }
            if type == 1 {                       // pointer
                let ss = Int((ctrl >> 3) & 0x03)
                let vvv = Int(ctrl & 0x07)
                var pointer: Int
                switch ss {
                case 0: pointer = vvv << 8 | Int(try byte(pos)); pos += 1
                case 1: pointer = ((vvv << 16) | Int(try byte(pos)) << 8 | Int(try byte(pos + 1))) + 2048; pos += 2
                case 2: pointer = ((vvv << 24) | Int(try byte(pos)) << 16 | Int(try byte(pos + 1)) << 8 | Int(try byte(pos + 2))) + 526_336; pos += 3
                default: pointer = Int(try byte(pos)) << 24 | Int(try byte(pos + 1)) << 16 | Int(try byte(pos + 2)) << 8 | Int(try byte(pos + 3)); pos += 4
                }
                let target = dataStart + pointer
                let (v, _) = try decode(at: target)
                return (v, pos)
            }
            var size = Int(ctrl & 0x1F)
            if size == 29 { size = 29 + Int(try byte(pos)); pos += 1 }
            else if size == 30 { size = 285 + Int(try byte(pos)) << 8 + Int(try byte(pos + 1)); pos += 2 }
            else if size == 31 { size = 65_821 + Int(try byte(pos)) << 16 + Int(try byte(pos + 1)) << 8 + Int(try byte(pos + 2)); pos += 3 }
            func raw(_ n: Int) throws -> Data { guard pos + n <= data.count else { throw ReaderError.corrupt("truncated value") }; return data.subdata(in: pos..<pos + n) }
            switch type {
            case 2:  let d = try raw(size); return (.string(String(decoding: d, as: UTF8.self)), pos + size)
            case 3:  guard size == 8 else { throw ReaderError.corrupt("double size") }; let d = try raw(8); return (.double(Double(bitPattern: d.reduce(0) { $0 << 8 | UInt64($1) })), pos + 8)
            case 4:  let d = try raw(size); return (.bytes(d), pos + size)
            case 5:  let d = try raw(size); return (.uint16(UInt16(d.reduce(0) { $0 << 8 | UInt64($1) })), pos + size)
            case 6:  let d = try raw(size); return (.uint32(UInt32(d.reduce(0) { $0 << 8 | UInt64($1) })), pos + size)
            case 7:
                var map: [String: Value] = [:]
                for _ in 0..<size {
                    let (k, p1) = try decode(at: pos); pos = p1
                    let (v, p2) = try decode(at: pos); pos = p2
                    if let key = k.stringValue { map[key] = v }
                }
                return (.map(map), pos)
            case 8:  let d = try raw(size); return (.int32(Int32(truncatingIfNeeded: d.reduce(0) { $0 << 8 | UInt64($1) })), pos + size)
            case 9:  let d = try raw(size); return (.uint64(d.reduce(0) { $0 << 8 | UInt64($1) }), pos + size)
            case 10: let d = try raw(size); return (.uint128(d), pos + size)
            case 11:
                var arr: [Value] = []
                for _ in 0..<size { let (v, p) = try decode(at: pos); arr.append(v); pos = p }
                return (.array(arr), pos)
            case 12: return (.null, pos)          // data cache container (not used by lookups)
            case 13: return (.null, pos)          // end marker
            case 14: return (.bool(size != 0), pos)
            case 15: guard size == 4 else { throw ReaderError.corrupt("float size") }; let d = try raw(4); return (.float(Float(bitPattern: UInt32(d.reduce(0) { $0 << 8 | UInt64($1) }))), pos + 4)
            default: throw ReaderError.corrupt("unknown type \(type)")
            }
        }

        private func byte(_ i: Int) throws -> UInt8 { guard i < data.count else { throw ReaderError.corrupt("truncated") }; return data[i] }
    }
}
