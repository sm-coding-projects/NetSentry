import Foundation

/// Framing for `.nsraw` capture files: a sequence of records, each
/// `u32 payloadLength | i64 receivedAt(µs) | u8 kind | u8 transport | u16 sourcePort | 16 bytes source IP | payload`
/// (all integers big-endian). Simple enough to read from Python for fixture curation.
public enum RawCaptureFormat {
    public static let headerSize = 4 + 8 + 1 + 1 + 2 + 16
    public static let magic = Data("NSRAW1\n".utf8)

    public static func encode(_ d: RawDatagram) -> Data {
        var out = Data(capacity: headerSize + d.payload.count)
        var len = UInt32(d.payload.count).bigEndian
        var ts = d.receivedAt.microseconds.bigEndian
        var port = d.sourcePort.bigEndian
        withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
        withUnsafeBytes(of: &ts) { out.append(contentsOf: $0) }
        out.append(d.kind == .ipfix ? 0 : 1)
        out.append(d.transport.rawValue)
        withUnsafeBytes(of: &port) { out.append(contentsOf: $0) }
        var ip = d.source.bytes
        if ip.count == 4 { ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] + ip }
        out.append(contentsOf: ip)
        out.append(d.payload)
        return out
    }

    /// Decodes a whole capture file; stops at the first truncated record.
    public static func decode(_ data: Data) -> [RawDatagram] {
        var out: [RawDatagram] = []
        var i = data.startIndex
        if data.starts(with: magic) { i += magic.count }
        while i + headerSize <= data.endIndex {
            let len = Int(UInt32(bigEndian: data[i..<i+4].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
            let ts = Int64(bigEndian: data[i+4..<i+12].withUnsafeBytes { $0.loadUnaligned(as: Int64.self) })
            let kind: ListenerKind = data[i+12] == 0 ? .ipfix : .syslog
            let transport = Transport(rawValue: data[i+13]) ?? .udp
            let port = UInt16(bigEndian: data[i+14..<i+16].withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) })
            let ip = IPAddress(bytes: Array(data[i+16..<i+32])) ?? IPAddress(v4: 0)
            let start = i + headerSize
            guard start + len <= data.endIndex else { break }
            out.append(RawDatagram(receivedAt: Timestamp(microseconds: ts), kind: kind, transport: transport, source: ip,
                                   sourcePort: port, localPort: 0, payload: Data(data[start..<start+len])))
            i = start + len
        }
        return out
    }
}
