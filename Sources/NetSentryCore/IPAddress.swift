import Foundation

/// IPv4 or IPv6 address stored as 128 bits (IPv4 is stored IPv4-mapped, ::ffff:a.b.c.d).
public struct IPAddress: Hashable, Sendable, Codable, CustomStringConvertible, Comparable {
    public let hi: UInt64
    public let lo: UInt64
    public let version: UInt8

    public init(v4 value: UInt32) {
        hi = 0
        lo = 0x0000_FFFF_0000_0000 | UInt64(value)
        version = 4
    }

    public init(v6 hi: UInt64, lo: UInt64) {
        self.hi = hi
        self.lo = lo
        self.version = 6
    }

    /// Bytes in network order: 4 for IPv4, 16 for IPv6. Returns nil for other lengths.
    public init?(bytes: some Collection<UInt8>) {
        switch bytes.count {
        case 4:
            var v: UInt32 = 0
            for b in bytes { v = (v << 8) | UInt32(b) }
            self.init(v4: v)
        case 16:
            var h: UInt64 = 0, l: UInt64 = 0
            for (i, b) in bytes.enumerated() {
                if i < 8 { h = (h << 8) | UInt64(b) } else { l = (l << 8) | UInt64(b) }
            }
            // IPv4-mapped IPv6 (::ffff:a.b.c.d) is normalized to IPv4 so both spellings compare equal.
            if h == 0, l >> 32 == 0xFFFF {
                self.init(v4: UInt32(truncatingIfNeeded: l))
            } else {
                self.init(v6: h, lo: l)
            }
        default:
            return nil
        }
    }

    public init?(_ text: String) {
        var v4 = in_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            self.init(v4: UInt32(bigEndian: v4.s_addr))
            return
        }
        var v6 = in6_addr()
        if text.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            let bytes = withUnsafeBytes(of: &v6) { Array($0) }
            self.init(bytes: bytes)
            return
        }
        return nil
    }

    public var v4Value: UInt32? { version == 4 ? UInt32(truncatingIfNeeded: lo) : nil }

    public var bytes: [UInt8] {
        if let v = v4Value {
            return [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
        }
        return (0..<8).map { UInt8((hi >> (56 - 8 * UInt64($0))) & 0xff) }
            + (0..<8).map { UInt8((lo >> (56 - 8 * UInt64($0))) & 0xff) }
    }

    /// Canonical text (dotted quad, or compressed IPv6 as produced by inet_ntop, lowercase).
    public var description: String {
        if let v = v4Value {
            return "\(v >> 24).\((v >> 16) & 0xff).\((v >> 8) & 0xff).\(v & 0xff)"
        }
        var addr = in6_addr()
        let b = bytes
        withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: b) }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &addr, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil else { return "::" }
        return String(cString: buf)
    }

    public static func < (lhs: IPAddress, rhs: IPAddress) -> Bool {
        lhs.hi != rhs.hi ? lhs.hi < rhs.hi : lhs.lo < rhs.lo
    }

    // MARK: Classification (RFC 1918, 4193, 4291, 6598, 3927, 5737)

    public var isLoopback: Bool {
        if let v = v4Value { return v >> 24 == 127 }
        return hi == 0 && lo == 1
    }
    public var isLinkLocal: Bool {
        if let v = v4Value { return v >> 16 == 0xA9FE }
        return (hi >> 54) == 0x3FA  // fe80::/10
    }
    public var isMulticast: Bool {
        if let v = v4Value { return v >> 28 == 0xE }
        return (hi >> 56) == 0xFF
    }
    public var isUnspecified: Bool { hi == 0 && (lo == 0 || (version == 4 && lo == 0x0000_FFFF_0000_0000)) }
    /// RFC 1918 + CGNAT 100.64/10 + IPv6 ULA fc00::/7.
    public var isPrivate: Bool {
        if let v = v4Value {
            return v >> 24 == 10 || v >> 20 == 0xAC1 || v >> 16 == 0xC0A8 || v >> 22 == 0x191
        }
        return (hi >> 57) == 0x7E
    }
    /// True for addresses that can never be a public Internet endpoint.
    public var isNonRoutable: Bool { isLoopback || isLinkLocal || isMulticast || isUnspecified || isPrivate }
}

/// CIDR prefix such as 192.168.1.0/24 or fd00::/8.
public struct IPPrefix: Hashable, Sendable, Codable, CustomStringConvertible {
    public let network: IPAddress
    public let prefixLength: UInt8

    public init(network: IPAddress, prefixLength: UInt8) {
        self.network = network
        self.prefixLength = min(prefixLength, network.version == 4 ? 32 : 128)
    }

    public init?(_ text: String) {
        let parts = text.split(separator: "/", maxSplits: 1)
        guard let addr = IPAddress(String(parts[0])) else { return nil }
        let len: UInt8
        if parts.count == 2 {
            guard let l = UInt8(parts[1]) else { return nil }
            len = l
        } else {
            len = addr.version == 4 ? 32 : 128
        }
        guard len <= (addr.version == 4 ? 32 : 128) else { return nil }
        self.init(network: addr, prefixLength: len)
    }

    public func contains(_ address: IPAddress) -> Bool {
        guard address.version == network.version else { return false }
        if network.version == 4 {
            guard let a = address.v4Value, let n = network.v4Value else { return false }
            if prefixLength == 0 { return true }
            let mask = prefixLength >= 32 ? UInt32.max : ~(UInt32.max >> prefixLength)
            return (a & mask) == (n & mask)
        }
        let len = Int(prefixLength)
        let hiBits = min(len, 64)
        let loBits = max(len - 64, 0)
        let hiMask: UInt64 = hiBits == 0 ? 0 : (hiBits >= 64 ? .max : ~(UInt64.max >> UInt64(hiBits)))
        let loMask: UInt64 = loBits == 0 ? 0 : (loBits >= 64 ? .max : ~(UInt64.max >> UInt64(loBits)))
        return (address.hi & hiMask) == (network.hi & hiMask) && (address.lo & loMask) == (network.lo & loMask)
    }

    public var description: String { "\(network)/\(prefixLength)" }
}

/// MAC address (EUI-48).
public struct MACAddress: Hashable, Sendable, Codable, CustomStringConvertible {
    public let value: UInt64  // lower 48 bits
    public init(value: UInt64) { self.value = value & 0xFFFF_FFFF_FFFF }
    public init?(_ text: String) {
        let hex = text.replacingOccurrences(of: ":", with: "").replacingOccurrences(of: "-", with: "")
        guard hex.count == 12, let v = UInt64(hex, radix: 16) else { return nil }
        self.init(value: v)
    }
    public var description: String {
        (0..<6).map { String(format: "%02x", (value >> (40 - 8 * UInt64($0))) & 0xff) }.joined(separator: ":")
    }
}
