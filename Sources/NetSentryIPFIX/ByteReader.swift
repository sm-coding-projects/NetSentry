import Foundation

/// Bounds-checked big-endian reader over a Data slice. Every read fails softly (nil) instead of trapping.
struct ByteReader {
    let data: Data
    private(set) var offset: Int
    let end: Int

    init(_ data: Data, offset: Int = 0, end: Int? = nil) {
        self.data = data
        self.offset = data.startIndex + offset
        self.end = min(data.endIndex, data.startIndex + (end ?? data.count))
    }

    var remaining: Int { end - offset }
    var isAtEnd: Bool { offset >= end }

    mutating func u8() -> UInt8? {
        guard remaining >= 1 else { return nil }
        defer { offset += 1 }
        return data[offset]
    }
    mutating func u16() -> UInt16? {
        guard remaining >= 2 else { return nil }
        let v = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        offset += 2
        return v
    }
    mutating func u32() -> UInt32? {
        guard remaining >= 4 else { return nil }
        var v: UInt32 = 0
        for i in 0..<4 { v = v << 8 | UInt32(data[offset + i]) }
        offset += 4
        return v
    }
    mutating func bytes(_ n: Int) -> Data? {
        guard n >= 0, remaining >= n else { return nil }
        defer { offset += n }
        return data.subdata(in: offset..<offset + n)
    }
    mutating func skip(_ n: Int) -> Bool {
        guard n >= 0, remaining >= n else { return false }
        offset += n
        return true
    }
    /// Sub-reader limited to `length` bytes starting at the current offset.
    func slice(length: Int) -> ByteReader? {
        guard length >= 0, remaining >= length else { return nil }
        return ByteReader(data, offset: offset - data.startIndex, end: offset - data.startIndex + length)
    }
}
