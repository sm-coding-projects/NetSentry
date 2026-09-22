import Foundation
import NetSentryCore

/// Last-resort classifier for lines no field parser claims: assigns the event family from the process name
/// (plus a few message prefixes) using a fixed table of daemons seen on UniFi gateways, access points and
/// switches. It extracts nothing and leaves `parseStatus` at `.partial`; the table entry is the whole
/// explanation and is recorded in `class.by`. Lines from a recognized UniFi device whose process is not in the
/// table become `.system`; anything else stays `.unknown`.
public struct ProcessTableParser: SyslogFamilyParser {
    public static let name = "process-table"
    public static let version: UInt16 = 1
    /// Decided per line.
    public static let family: EventType = .unknown
    public static let classifiesOnly = true
    public static let verified = true
    public static let description = "Family by process name for UniFi gateway, AP and switch daemons (no field extraction)"

    public init() {}

    public func parse(_ e: inout SyslogEvent) -> Bool {
        guard let app = e.appName?.lowercased(), !app.isEmpty else { return false }
        let unifiDevice = e.attributes[UniFiDeviceTag.deviceAttribute] == "true"
        guard let (type, why) = Self.classify(app: app, message: e.message, unifiDevice: unifiDevice) else { return false }
        e.eventType = type
        e.attributes["class.by"] = why
        return true
    }

    static func classify(app: String, message: String, unifiDevice: Bool) -> (EventType, String)? {
        if let t = exact[app] { return (t, "process:\(app)") }
        if app == "kernel" {
            if message.hasPrefix("[") || message.hasPrefix("wlan:") {
                if message.contains("wlan: ") { return (.client, "kernel:wlan") }
                if message.contains("[STA_TRACKER] DNS") { return (.dns, "kernel:sta-tracker-dns") }
                if message.contains("[DHCP-SM]") { return (.dhcp, "kernel:dhcp-sm") }
            }
            return (.system, "process:kernel")
        }
        if app == "switch" {
            return message.hasPrefix("DHCP_SNP") ? (.dhcp, "switch:dhcp-snooping") : (.unifiOther, "process:switch")
        }
        for (prefix, t) in prefixes where app.hasPrefix(prefix) { return (t, "process-prefix:\(prefix)") }
        return unifiDevice ? (.system, "unifi-device-default") : nil
    }

    static let exact: [String: EventType] = {
        var m: [String: EventType] = [:]
        func add(_ t: EventType, _ names: [String]) { for n in names { m[n] = t } }
        add(.client, ["hostapd", "stahtd", "wevent", "wpa_supplicant"])
        add(.dhcp, ["udhcpc", "dnsmasq-dhcp", "odhcpd", "dhclient", "dhcpcd", "dhcpd", "udhcpd"])
        add(.dns, ["dnsmasq", "coredns", "corednssc", "dns-cache-db", "unbound", "named"])
        add(.auth, ["sshd", "sshd-session", "dropbear", "sudo", "cron", "crond", "su", "login", "pam_unix", "systemd-logind"])
        add(.vpn, ["teleportd", "wireguard", "wg-quick", "openvpn", "charon", "strongswan", "ipsec", "xl2tpd"])
        add(.ids, ["suricata", "suricata-rule", "ubnt-idsips-daemon", "idsips_check_subscription", "ips-update.sh", "ips-update"])
        add(.firewall, ["ulogd", "nft", "iptables", "ip6tables", "ufw"])
        add(.unifiOther, ["mcad", "mca-ctrl", "mca-monitor", "mca", "mca-db", "mca-er", "syswrapper", "cfgmtd", "swctrl", "dpi-flow-stats",
                          "utm_check_subscription", "ace_reporter", "inf", "inf-db", "inf-er", "infx-er", "nd", "uenv", "fls_dev", "sif-db",
                          "mcast", "linkcheck", "fprint-sig-update", "wifiman-proxy-cert", "start.sh", "pre-start.sh"])
        return m
    }()

    /// Checked after `exact`, in order.
    static let prefixes: [(String, EventType)] = [
        ("unifi-", .unifiOther), ("ubnt-", .unifiOther), ("ubios-", .unifiOther), ("wifiman-", .unifiOther),
        ("systemd", .system), ("ppp", .system),
    ]
}
