import Foundation
import NetSentryCore
import NetSentryPersistence
import os

/// A resolved client identity.
public struct ClientIdentity: Sendable, Hashable, Codable, Identifiable {
    public var id: Int64
    public var displayName: String?
    public var hostname: String?
    public var primaryMAC: String?
    public var vlanID: Int?
    public var networkID: String?
    public var firstSeen: Timestamp
    public var lastSeen: Timestamp
    public var notes: String?
    public var trusted: Bool
    public var createdBy: String
    public var addresses: [String]
    public var tags: [String]
    public var label: String { displayName ?? hostname ?? addresses.first ?? "client \(id)" }
    public init(id: Int64, displayName: String? = nil, hostname: String? = nil, primaryMAC: String? = nil, vlanID: Int? = nil, networkID: String? = nil,
                firstSeen: Timestamp, lastSeen: Timestamp, notes: String? = nil, trusted: Bool = false, createdBy: String = "auto", addresses: [String] = [], tags: [String] = []) {
        self.id = id; self.displayName = displayName; self.hostname = hostname; self.primaryMAC = primaryMAC; self.vlanID = vlanID; self.networkID = networkID
        self.firstSeen = firstSeen; self.lastSeen = lastSeen; self.notes = notes; self.trusted = trusted; self.createdBy = createdBy; self.addresses = addresses; self.tags = tags
    }
}

/// Maps addresses to clients over time. Sources, in order of confidence: user edits, DHCP leases (syslog),
/// MAC addresses carried by IPFIX/netfilter records, and finally "an internal address that talks" (auto-created).
/// The historical mapping (`client_addresses` with validity intervals) is what enrichment consults, so a
/// record enriched last month keeps the identity that was valid then.
public actor EntityResolver {
    private let meta: MetaStore
    private let log = Log.logger("entities", process: "collector")
    private let internalPrefixes: [IPPrefix]
    private var byIP: [IPAddress: Int64] = [:]             // current mapping cache
    private var byMAC: [String: Int64] = [:]
    private var macsByClient: [Int64: Set<String>] = [:]
    private var lastSeen: [Int64: Timestamp] = [:]
    private var lastSeenFlushed: [Int64: Timestamp] = [:]
    public private(set) var changes: [IdentityChange] = []

    public struct IdentityChange: Sendable, Hashable {
        public enum Kind: String, Sendable { case created, addressAssigned, addressMoved, hostnameLearned, macLearned }
        public var kind: Kind; public var clientID: Int64; public var ip: String?; public var detail: String; public var at: Timestamp
    }

    public init(meta: MetaStore, internalPrefixes: [IPPrefix]) async throws {
        self.meta = meta
        self.internalPrefixes = internalPrefixes
        for row in try meta.db.query("SELECT ip, client_id FROM client_addresses WHERE valid_to IS NULL") {
            if let ip = row.string("ip").flatMap(IPAddress.init), let id = row.int64("client_id") { byIP[ip] = id }
        }
        for row in try meta.db.query("SELECT mac, client_id FROM client_macs WHERE valid_to IS NULL") {
            if let mac = row.string("mac"), let id = row.int64("client_id") { byMAC[mac] = id; macsByClient[id, default: []].insert(mac) }
        }
    }

    public func isInternal(_ ip: IPAddress) -> Bool { ip.isPrivate || ip.isLinkLocal || internalPrefixes.contains { $0.contains(ip) } }

    /// Current client for an address (nil for external or unknown addresses).
    public func clientID(for ip: IPAddress) -> Int64? { byIP[ip] }

    /// Client that owned `ip` at `time` according to the address history.
    public func clientID(for ip: IPAddress, at time: Timestamp) throws -> Int64? {
        if let row = try meta.db.query("SELECT client_id FROM client_addresses WHERE ip = ? AND valid_from <= ? AND (valid_to IS NULL OR valid_to > ?) ORDER BY valid_from DESC LIMIT 1", [ip, time, time]).first {
            return row.int64("client_id")
        }
        return nil
    }

    /// Observes an internal address (and optional MAC/hostname) at `time`; creates or updates identities.
    @discardableResult
    public func observe(ip: IPAddress, mac: String? = nil, hostname: String? = nil, vlan: UInt16? = nil, at time: Timestamp, source: String) throws -> Int64? {
        guard isInternal(ip), !ip.isMulticast, !ip.isLinkLocal, !ip.isUnspecified else { return nil }
        let mac = mac?.lowercased()
        var id = byIP[ip]
        if let mac {
            let owner = byMAC[mac]
            if let current = id, owner != current, !(macsByClient[current] ?? []).isEmpty || owner != nil {
                // A different device appears to answer on this address (DHCP reassignment). One garbled or spoofed
                // record must not rewrite history, so the move happens only after `moveThreshold` consecutive
                // observations of the same new MAC; until then the flow stays attributed to the current owner.
                // A DHCP acknowledgement is the server's own statement of the lease and moves the address at once.
                let pending = source == "dhcp" ? (mac: mac, count: Self.moveThreshold, firstSeen: time) : pendingMoves[ip]
                if pending?.mac == mac, let p = pending, p.count + 1 >= Self.moveThreshold {
                    pendingMoves[ip] = nil
                    try meta.db.run("UPDATE client_addresses SET valid_to = ? WHERE ip = ? AND client_id = ? AND valid_to IS NULL", [p.firstSeen, ip, current])
                    changes.append(.init(kind: .addressMoved, clientID: owner ?? -1, ip: ip.description, detail: "from client \(current)", at: p.firstSeen))
                    byIP[ip] = nil
                    id = owner
                } else {
                    pendingMoves[ip] = pending?.mac == mac ? (mac, p1(pending), pending!.firstSeen) : (mac, 1, time)
                    lastSeen[current] = max(lastSeen[current] ?? time, time)
                    return current
                }
            } else if id == nil {
                id = owner
            }
        }
        if id == nil {
            id = try createClient(ip: ip, mac: mac, hostname: hostname, vlan: vlan, at: time, source: source)
        }
        guard let clientID = id else { return nil }
        if byIP[ip] != clientID {
            try meta.db.run("INSERT INTO client_addresses (client_id, ip, valid_from, valid_to, source, confidence) VALUES (?, ?, ?, NULL, ?, ?)", [clientID, ip, time, source, mac != nil ? 1.0 : 0.6])
            byIP[ip] = clientID
            changes.append(.init(kind: .addressAssigned, clientID: clientID, ip: ip.description, detail: source, at: time))
        }
        if let mac, byMAC[mac] == clientID { pendingMoves[ip] = nil }
        if let mac, byMAC[mac] == nil {
            try meta.db.run("INSERT OR IGNORE INTO client_macs (client_id, mac, valid_from, valid_to, source) VALUES (?, ?, ?, NULL, ?)", [clientID, mac, time, source])
            try meta.db.run("UPDATE clients SET primary_mac = COALESCE(primary_mac, ?) WHERE id = ?", [mac, clientID])
            byMAC[mac] = clientID
            macsByClient[clientID, default: []].insert(mac)
            changes.append(.init(kind: .macLearned, clientID: clientID, ip: ip.description, detail: mac, at: time))
        }
        if let hostname, !hostname.isEmpty, hostname != "*" {
            let n = try meta.db.run("UPDATE clients SET hostname = ? WHERE id = ? AND (hostname IS NULL OR hostname != ?)", [hostname, clientID, hostname])
            if n > 0 { changes.append(.init(kind: .hostnameLearned, clientID: clientID, ip: ip.description, detail: hostname, at: time)) }
        }
        if let vlan { try meta.db.run("UPDATE clients SET vlan_id = COALESCE(vlan_id, ?) WHERE id = ?", [Int(vlan), clientID]) }
        lastSeen[clientID] = max(lastSeen[clientID] ?? time, time)
        return clientID
    }

    private func createClient(ip: IPAddress, mac: String?, hostname: String?, vlan: UInt16?, at time: Timestamp, source: String) throws -> Int64 {
        try meta.db.run("INSERT INTO clients (display_name, hostname, primary_mac, vlan_id, first_seen, last_seen, created_by) VALUES (NULL, ?, ?, ?, ?, ?, ?)",
                        [hostname, mac, vlan.map(Int.init), time, time, source])
        let id = meta.db.lastInsertRowID
        changes.append(.init(kind: .created, clientID: id, ip: ip.description, detail: source, at: time))
        return id
    }

    /// Writes accumulated last-seen timestamps (called periodically, not per record).
    public func flushLastSeen() throws {
        let pending = lastSeen.filter { lastSeenFlushed[$0.key] != $0.value }
        guard !pending.isEmpty else { return }
        try meta.db.transaction {
            for (id, t) in pending { try meta.db.run("UPDATE clients SET last_seen = MAX(last_seen, ?) WHERE id = ?", [t, id]) }
        }
        for (id, t) in pending { lastSeenFlushed[id] = t }
    }

    /// Consecutive observations of a new MAC on an address before the address is reassigned.
    public static let moveThreshold = 3
    private var pendingMoves: [IPAddress: (mac: String, count: Int, firstSeen: Timestamp)] = [:]
    private func p1(_ p: (mac: String, count: Int, firstSeen: Timestamp)?) -> Int { (p?.count ?? 0) + 1 }

    public func drainChanges() -> [IdentityChange] { defer { changes.removeAll() }; return changes }

    // MARK: - User edits

    public func client(id: Int64) throws -> ClientIdentity? { try Self.clients(meta: meta, whereSQL: "c.id = ?", params: [id]).first }

    public func allClients() throws -> [ClientIdentity] { try Self.clients(meta: meta, whereSQL: "c.merged_into IS NULL", params: []) }

    public static func clients(meta: MetaStore, whereSQL: String, params: [any SQLBindable]) throws -> [ClientIdentity] {
        try meta.db.query("SELECT c.*, (SELECT GROUP_CONCAT(ip, ',') FROM client_addresses a WHERE a.client_id = c.id AND a.valid_to IS NULL) AS ips, (SELECT GROUP_CONCAT(t.name, ',') FROM client_tags ct JOIN tags t ON t.id = ct.tag_id WHERE ct.client_id = c.id) AS tags FROM clients c WHERE \(whereSQL) ORDER BY c.last_seen DESC", params).map { r in
            ClientIdentity(id: r.int64("id") ?? 0, displayName: r.string("display_name"), hostname: r.string("hostname"), primaryMAC: r.string("primary_mac"), vlanID: r.int("vlan_id"),
                           networkID: r.string("network_id"), firstSeen: r.timestamp("first_seen") ?? .now, lastSeen: r.timestamp("last_seen") ?? .now, notes: r.string("notes"),
                           trusted: r.bool("trusted"), createdBy: r.string("created_by") ?? "auto",
                           addresses: (r.string("ips") ?? "").split(separator: ",").map(String.init), tags: (r.string("tags") ?? "").split(separator: ",").map(String.init))
        }
    }

    public func rename(_ id: Int64, to name: String?) throws { try meta.db.run("UPDATE clients SET display_name = ?, created_by = 'user' WHERE id = ?", [name?.isEmpty == true ? nil : name, id]) }
    public func setNotes(_ id: Int64, _ notes: String?) throws { try meta.db.run("UPDATE clients SET notes = ? WHERE id = ?", [notes, id]) }
    public func setTrusted(_ id: Int64, _ trusted: Bool) throws { try meta.db.run("UPDATE clients SET trusted = ? WHERE id = ?", [trusted, id]) }

    public func setTags(_ id: Int64, _ tags: [String]) throws {
        try meta.db.transaction {
            try meta.db.run("DELETE FROM client_tags WHERE client_id = ?", [id])
            for t in Set(tags.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }) {
                try meta.db.run("INSERT OR IGNORE INTO tags (name) VALUES (?)", [t])
                try meta.db.run("INSERT OR IGNORE INTO client_tags (client_id, tag_id) SELECT ?, id FROM tags WHERE name = ?", [id, t])
            }
        }
    }

    /// Moves every address and MAC of `source` onto `target`, keeping history; `source` becomes an alias.
    public func merge(_ source: Int64, into target: Int64) throws {
        guard source != target else { return }
        try meta.db.transaction {
            try meta.db.run("UPDATE client_addresses SET client_id = ? WHERE client_id = ?", [target, source])
            try meta.db.run("UPDATE client_macs SET client_id = ? WHERE client_id = ?", [target, source])
            try meta.db.run("UPDATE clients SET merged_into = ? WHERE id = ?", [target, source])
            try meta.db.run("UPDATE clients SET first_seen = MIN(first_seen, (SELECT first_seen FROM clients WHERE id = ?)), primary_mac = COALESCE(primary_mac, (SELECT primary_mac FROM clients WHERE id = ?)), hostname = COALESCE(hostname, (SELECT hostname FROM clients WHERE id = ?)) WHERE id = ?", [source, source, source, target])
        }
        for (ip, id) in byIP where id == source { byIP[ip] = target }
        for (mac, id) in byMAC where id == source { byMAC[mac] = target }
        macsByClient[target, default: []].formUnion(macsByClient.removeValue(forKey: source) ?? [])
    }

    /// Splits `ip` (and its current interval) off `clientID` into a brand-new client from `time` onward.
    @discardableResult
    public func split(ip: IPAddress, from clientID: Int64, at time: Timestamp) throws -> Int64 {
        let newID = try createClient(ip: ip, mac: nil, hostname: nil, vlan: nil, at: time, source: "user")
        try meta.db.transaction {
            try meta.db.run("UPDATE client_addresses SET valid_to = ? WHERE ip = ? AND client_id = ? AND valid_to IS NULL", [time, ip, clientID])
            try meta.db.run("INSERT INTO client_addresses (client_id, ip, valid_from, valid_to, source, confidence) VALUES (?, ?, ?, NULL, 'user', 1.0)", [newID, ip, time])
        }
        byIP[ip] = newID
        return newID
    }
}
