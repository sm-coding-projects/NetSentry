import Foundation
import NetSentryCore

public struct ParserDescriptor: Sendable, Hashable, Codable {
    public let name: String
    public let version: UInt16
    public let family: EventType
    public let verified: Bool
    public let description: String
}

/// Ordered list of family parsers; first claim wins. Order matters: specific formats before generic ones.
public enum ParserRegistry {
    public static let defaultParsers: [any SyslogFamilyParser] = [
        SuricataFastParser(), NetfilterParser(), DnsmasqDHCPParser(), DnsmasqDNSParser(), OpenSSHParser(),
    ]

    public static var descriptors: [ParserDescriptor] {
        defaultParsers.map { p in
            let t = type(of: p)
            return ParserDescriptor(name: t.name, version: t.version, family: t.family, verified: t.verified, description: t.description)
        } + [
            ParserDescriptor(name: SyslogParser.headerParserName, version: SyslogParser.headerParserVersion, family: .unknown, verified: true, description: "RFC 3164 / RFC 5424 header, PRI, timestamps, structured data"),
            ParserDescriptor(name: SyslogParser.fallbackParserName, version: SyslogParser.fallbackParserVersion, family: .unknown, verified: true, description: "Keeps unrecognized messages verbatim as unparsed events"),
        ]
    }

    /// Highest version across parsers; bumping any parser makes stored events eligible for reprocessing.
    public static var combinedVersion: String { descriptors.map { "\($0.name)=\($0.version)" }.sorted().joined(separator: ",") }
}
