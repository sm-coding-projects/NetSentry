import Foundation

/// Static IANA service names for well-known ports (no network lookup). Extend via `ServiceNames.custom`.
public enum ServiceNames {
    nonisolated(unsafe) public static var custom: [String: String] = [:]   // "tcp/8443" → "https-alt"

    private static let table: [UInt16: (tcp: String?, udp: String?)] = [
        20: ("ftp-data", nil), 21: ("ftp", nil), 22: ("ssh", nil), 23: ("telnet", nil), 25: ("smtp", nil), 53: ("dns", "dns"), 67: (nil, "dhcp"), 68: (nil, "dhcp"),
        69: (nil, "tftp"), 80: ("http", "http"), 88: ("kerberos", "kerberos"), 110: ("pop3", nil), 111: ("rpcbind", "rpcbind"), 119: ("nntp", nil), 123: (nil, "ntp"),
        135: ("msrpc", "msrpc"), 137: (nil, "netbios-ns"), 138: (nil, "netbios-dgm"), 139: ("netbios-ssn", nil), 143: ("imap", nil), 161: (nil, "snmp"), 162: (nil, "snmp-trap"),
        179: ("bgp", nil), 194: ("irc", nil), 389: ("ldap", "ldap"), 443: ("https", "quic"), 445: ("smb", nil), 465: ("smtps", nil), 500: (nil, "isakmp"), 514: ("syslog", "syslog"),
        515: ("printer", nil), 548: ("afp", nil), 554: ("rtsp", "rtsp"), 587: ("submission", nil), 631: ("ipp", "ipp"), 636: ("ldaps", nil), 853: ("dns-over-tls", "dns-over-quic"),
        873: ("rsync", nil), 993: ("imaps", nil), 995: ("pop3s", nil), 1194: ("openvpn", "openvpn"), 1433: ("mssql", nil), 1521: ("oracle", nil), 1701: (nil, "l2tp"),
        1723: ("pptp", nil), 1883: ("mqtt", nil), 1900: (nil, "ssdp"), 2049: ("nfs", "nfs"), 2055: (nil, "netflow"), 3074: ("xbox-live", "xbox-live"), 3128: ("http-proxy", nil),
        3306: ("mysql", nil), 3389: ("rdp", "rdp"), 3478: ("stun", "stun"), 4500: (nil, "ipsec-nat-t"), 4739: (nil, "ipfix"), 5000: ("upnp", nil), 5060: ("sip", "sip"),
        5061: ("sips", nil), 5223: ("apple-push", nil), 5228: ("google-play", nil), 5353: (nil, "mdns"), 5432: ("postgresql", nil), 5514: ("syslog-alt", "syslog-alt"),
        5900: ("vnc", nil), 6379: ("redis", nil), 7000: ("airplay", nil), 8000: ("http-alt", nil), 8080: ("http-alt", nil), 8443: ("https-alt", nil), 8883: ("mqtts", nil),
        9000: ("cslistener", nil), 9100: ("jetdirect", nil), 10001: (nil, "unifi-discovery"), 27017: ("mongodb", nil), 32400: ("plex", nil), 51820: (nil, "wireguard"),
        62078: ("apple-mobdev", nil), 5001: ("synology", nil), 8291: ("winbox", nil),
    ]

    public static func name(port: UInt16, protocolNumber: UInt8) -> String? {
        let proto = protocolNumber == 6 ? "tcp" : (protocolNumber == 17 ? "udp" : nil)
        if let proto, let c = custom["\(proto)/\(port)"] { return c }
        guard let e = table[port] else { return nil }
        switch protocolNumber {
        case 6: return e.tcp ?? e.udp
        case 17: return e.udp ?? e.tcp
        default: return e.tcp ?? e.udp
        }
    }
}
