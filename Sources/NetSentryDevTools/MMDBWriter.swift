import Foundation
import NetSentryCore

/// Minimal MaxMind DB writer for tests and demo data: builds a 24-bit-record IPv6 search tree (IPv4 under
/// ::ffff:0:0/96 is *not* used; IPv4 is mapped under ::/96 as MaxMind does) from a list of prefixes.
public struct MMDBWriter {
    public struct Entry { public var prefix: IPPrefix; public var record: [String: Any]
        public init(prefix: IPPrefix, record: [String: Any]) { self.prefix = prefix; self.record = record } }

    private final class Node { var children: [Node?] = [nil, nil]; var dataIndex: Int? }

    public var databaseType = "NetSentry-Test"
    public var languages = ["en"]
    public var description = ["en": "synthetic database for tests"]

    public init() {}

    public func build(_ entries: [Entry]) -> Data {
        let root = Node()
        var records: [[String: Any]] = []
        for e in entries {
            records.append(e.record)
            let bits = Self.bits(of: e.prefix)
            var node = root
            for b in bits {
                if node.children[b] == nil { node.children[b] = Node() }
                node = node.children[b]!
            }
            node.dataIndex = records.count - 1
        }
        // Number nodes breadth-first; leaves with data become data pointers, empty leaves → nodeCount.
        var nodes: [Node] = []
        var queue = [root]
        while !queue.isEmpty {
            let n = queue.removeFirst()
            nodes.append(n)
            for c in n.children { if let c, c.dataIndex == nil { queue.append(c) } }
        }
        let nodeCount = nodes.count
        var index: [ObjectIdentifier: Int] = [:]
        for (i, n) in nodes.enumerated() { index[ObjectIdentifier(n)] = i }
        // Data section
        var dataSection = Data()
        var offsets: [Int] = []
        for r in records { offsets.append(dataSection.count); dataSection.append(Self.encode(r)) }
        var tree = Data()
        for n in nodes {
            for c in n.children {
                let value: Int
                if let c {
                    if let d = c.dataIndex { value = nodeCount + 16 + offsets[d] } else { value = index[ObjectIdentifier(c)]! }
                } else { value = nodeCount }
                tree.append(UInt8((value >> 16) & 0xff)); tree.append(UInt8((value >> 8) & 0xff)); tree.append(UInt8(value & 0xff))
            }
        }
        var out = tree
        out.append(Data(count: 16))
        out.append(dataSection)
        out.append(Data([0xAB, 0xCD, 0xEF]) + Data("MaxMind.com".utf8))
        out.append(Self.encode(["node_count": UInt32(nodeCount), "record_size": UInt16(24), "ip_version": UInt16(6), "database_type": databaseType,
                                "languages": languages, "binary_format_major_version": UInt16(2), "binary_format_minor_version": UInt16(0),
                                "build_epoch": UInt64(Date().timeIntervalSince1970), "description": description]))
        return out
    }

    /// 128-bit path for a prefix (IPv4 mapped under ::/96 as in MaxMind IPv6 trees).
    static func bits(of p: IPPrefix) -> [Int] {
        var bytes = p.network.bytes
        var len = Int(p.prefixLength)
        if p.network.version == 4 { bytes = [UInt8](repeating: 0, count: 12) + bytes; len += 96 }
        return (0..<len).map { Int((bytes[$0 / 8] >> (7 - UInt8($0 % 8))) & 1) }
    }

    static func control(_ type: Int, _ size: Int) -> Data {
        var d = Data()
        let t = type < 8 ? type : 0
        func sizeBytes() -> (UInt8, Data) {
            if size < 29 { return (UInt8(size), Data()) }
            if size < 285 { return (29, Data([UInt8(size - 29)])) }
            if size < 65_821 { let s = size - 285; return (30, Data([UInt8(s >> 8), UInt8(s & 0xff)])) }
            let s = size - 65_821; return (31, Data([UInt8(s >> 16), UInt8((s >> 8) & 0xff), UInt8(s & 0xff)]))
        }
        let (s, extra) = sizeBytes()
        d.append(UInt8(t << 5) | s)
        if type >= 8 { d.append(UInt8(type - 7)) }
        d.append(extra)
        return d
    }

    static func encode(_ v: Any) -> Data {
        switch v {
        case let s as String: let b = Data(s.utf8); return control(2, b.count) + b
        case let d as Double: var x = d.bitPattern.bigEndian; return control(3, 8) + Data(bytes: &x, count: 8)
        case let u as UInt16: return control(5, 2) + Data([UInt8(u >> 8), UInt8(u & 0xff)])
        case let u as UInt32: return control(6, 4) + Data([UInt8(u >> 24), UInt8((u >> 16) & 0xff), UInt8((u >> 8) & 0xff), UInt8(u & 0xff)])
        case let u as UInt64: return control(9, 8) + Data((0..<8).map { UInt8((u >> (56 - 8 * UInt64($0))) & 0xff) })
        case let i as Int: return encode(UInt32(i))
        case let b as Bool: return control(14, b ? 1 : 0)
        case let a as [Any]: return a.reduce(control(11, a.count)) { $0 + encode($1) }
        case let m as [String: Any]:
            var d = control(7, m.count)
            for (k, val) in m.sorted(by: { $0.key < $1.key }) { d.append(encode(k)); d.append(encode(val)) }
            return d
        default: return control(2, 0)
        }
    }
}
