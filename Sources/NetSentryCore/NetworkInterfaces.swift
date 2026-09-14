import Foundation

/// An interface with an IPv4/IPv6 address the setup wizard and settings can list.
public struct NetworkInterfaceInfo: Sendable, Hashable, Identifiable, Codable {
    public var id: String { name }
    public var name: String
    public var addresses: [String]
    public var isUp: Bool
    public init(name: String, addresses: [String], isUp: Bool) { self.name = name; self.addresses = addresses; self.isUp = isUp }
}

public enum NetworkInterfaces {
    /// Enumerates interfaces with unicast addresses via getifaddrs, excluding loopback and link-local IPv6.
    public static func list(includeLoopback: Bool = false) -> [NetworkInterfaceInfo] {
        var result: [String: NetworkInterfaceInfo] = [:]
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return [] }
        defer { freeifaddrs(ifap) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            defer { p = cur.pointee.ifa_next }
            guard let sa = cur.pointee.ifa_addr else { continue }
            let family = Int32(sa.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            let name = String(cString: cur.pointee.ifa_name)
            let flags = Int32(cur.pointee.ifa_flags)
            let isLoop = (flags & IFF_LOOPBACK) != 0
            if isLoop && !includeLoopback { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let len = family == AF_INET ? socklen_t(MemoryLayout<sockaddr_in>.size) : socklen_t(MemoryLayout<sockaddr_in6>.size)
            guard getnameinfo(sa, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            var addr = String(cString: host)
            if let pct = addr.firstIndex(of: "%") { addr = String(addr[..<pct]) }
            if let ip = IPAddress(addr), ip.isLinkLocal { continue }
            let isUp = (flags & IFF_UP) != 0 && (flags & IFF_RUNNING) != 0
            result[name, default: NetworkInterfaceInfo(name: name, addresses: [], isUp: isUp)].addresses.append(addr)
        }
        return result.values.sorted { $0.name < $1.name }
    }
}
