import Foundation
import NetSentryCore

/// OpenSSH `sshd` authentication lines (`Accepted publickey for admin from 192.168.1.5 port 5100 ssh2`).
public struct OpenSSHParser: SyslogFamilyParser {
    public static let name = "openssh-auth"
    public static let version: UInt16 = 1
    public static let family: EventType = .auth
    public static let verified = false
    public static let description = "sshd Accepted/Failed/Invalid user/Disconnected lines"

    public init() {}

    public func parse(_ e: inout SyslogEvent) -> Bool {
        let msg = e.message
        let isSSH = (e.appName?.lowercased().hasPrefix("sshd") ?? false) || msg.hasSuffix(" ssh2") || msg.contains("Invalid user ")
        guard isSSH, let m = msg.range(of: #"^(Accepted|Failed|Invalid user|Disconnected from|Received disconnect from|Connection closed by)"#, options: .regularExpression) else { return false }
        let verb = String(msg[m])
        e.attributes["auth.event"] = verb
        e.attributes["auth.result"] = verb == "Accepted" ? "success" : (verb == "Failed" || verb == "Invalid user" ? "failure" : "info")
        if let r = msg.range(of: #" for (invalid user )?(\S+) from "#, options: .regularExpression) {
            let words = msg[r].split(separator: " ")
            if let user = words.dropLast().last { e.username = String(user) }
        } else if verb == "Invalid user", let r = msg.range(of: #"Invalid user (\S+) from"#, options: .regularExpression) {
            e.username = String(msg[r].split(separator: " ")[2])
        }
        if let r = msg.range(of: #"from (\S+) port (\d+)"#, options: .regularExpression) {
            let parts = msg[r].split(separator: " ")
            if parts.count >= 4 { e.srcIP = IPAddress(String(parts[1])); e.srcPort = UInt16(parts[3]) }
        } else if let r = msg.range(of: #"from (\S+)"#, options: .regularExpression) {
            e.srcIP = IPAddress(String(msg[r].split(separator: " ")[1]))
        }
        if let r = msg.range(of: #"^(Accepted|Failed) (\S+) for"#, options: .regularExpression) {
            e.attributes["auth.method"] = String(msg[r].split(separator: " ")[1])
        }
        return true
    }
}
