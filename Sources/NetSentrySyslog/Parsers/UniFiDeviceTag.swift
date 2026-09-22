import Foundation
import NetSentryCore

/// UniFi devices wrap their syslog lines in shapes the plain RFC 3164 tag grammar rejects, so the header
/// parser leaves `appName` empty and the whole remainder in `message`. Observed on a UCG Fiber, U6-Pro
/// access points and USW switches:
///
/// * Access points and switches: `<mac12>,<model>-<firmware>: <tag>[pid]: message`, e.g.
///   `0cea14e31de9,U6-Pro-6.8.2+15592: /usr/sbin/hostapd[4628]: ap_handle_timer: ...`
/// * The gateway (syslog-ng) repeats its hostname: `UCG-Fiber UCG-Fiber sudo[671885]: ...`
/// * Tags may carry a path (`/usr/sbin/hostapd`), be empty (`: wevent[4278]:`) or be doubled
///   (`stahtd: stahtd[28816]:`, `syslog: swctrl[4064]:`).
///
/// This step normalizes those shapes in place: it records the device MAC / model / firmware, strips the
/// wrapper and fills `appName` / `procID` from the real tag. `raw` is never touched.
public enum UniFiDeviceTag {
    public static let name = "unifi-device-tag"
    public static let version: UInt16 = 1
    public static let description = "UniFi AP/switch `<mac>,<model>-<fw>:` wrappers, repeated gateway hostnames, path/empty/doubled tags"

    /// Set to "true" when the line came through a recognized UniFi wrapper.
    public static let deviceAttribute = "unifi.device"

    static func normalize(_ e: inout SyslogEvent) {
        var s = Substring(e.message)
        var recognized = false

        if let (mac, modelFW, rest) = splitDevicePrefix(s) {
            e.deviceID = mac.description
            let (model, fw) = splitModelFirmware(modelFW)
            e.attributes["unifi.model"] = model
            if let fw { e.attributes["unifi.firmware"] = fw }
            s = rest
            recognized = true
        } else if e.appName == nil, let host = e.hostname, !host.isEmpty, s.hasPrefix(host + " ") {
            s = s.dropFirst(host.count + 1)
            SyslogLex.skipSpaces(&s)
            recognized = true
        }

        if recognized {
            e.attributes[deviceAttribute] = "true"
            takeTag(&s, into: &e)
            e.message = String(s)
        } else if let app = e.appName, app.contains("/") {
            // Plain lines can still carry a path tag (`/usr/bin/teleportd[3875]`); keep the basename as the app.
            e.attributes["proc.path"] = app
            e.appName = app.split(separator: "/").last.map(String.init) ?? app
        }
    }

    // MARK: - Pieces

    /// `<12 hex>,<model-fw>: ` → (MAC, model-fw, remainder).
    static func splitDevicePrefix(_ s: Substring) -> (MACAddress, Substring, Substring)? {
        guard s.count > 14 else { return nil }
        let macEnd = s.index(s.startIndex, offsetBy: 12)
        let hex = s[s.startIndex..<macEnd]
        guard hex.allSatisfy(\.isHexDigit), s[macEnd] == ",", let mac = MACAddress(String(hex)) else { return nil }
        let rest = s[s.index(after: macEnd)...]
        guard let colon = rest.firstIndex(of: ":"), rest.distance(from: rest.startIndex, to: colon) <= 48 else { return nil }
        let modelFW = rest[rest.startIndex..<colon]
        guard !modelFW.isEmpty, !modelFW.contains(" ") else { return nil }
        var after = rest[rest.index(after: colon)...]
        guard after.isEmpty || after.first == " " else { return nil }
        SyslogLex.skipSpaces(&after)
        return (mac, modelFW, after)
    }

    /// `U6-Pro-6.8.2+15592` → ("U6-Pro", "6.8.2+15592"); `USW_FLEX_MINI-2.1.6.762` → ("USW_FLEX_MINI", "2.1.6.762").
    static func splitModelFirmware(_ t: Substring) -> (String, String?) {
        let text = String(t)
        if let r = text.range(of: #"-\d+\.\d+\S*$"#, options: .regularExpression), r.lowerBound > text.startIndex {
            return (String(text[text.startIndex..<r.lowerBound]), String(text[text.index(after: r.lowerBound)...]))
        }
        return (text, nil)
    }

    struct Tag { let name: String; let pid: String?; let end: Substring.Index }

    /// Consumes `[/path/]name[pid]: ` (an empty `: ` tag before it is skipped). A doubled `name: name[pid]: ` or
    /// `syslog: name[pid]: ` resolves to the inner tag.
    static func takeTag(_ s: inout Substring, into e: inout SyslogEvent) {
        SyslogLex.skipSpaces(&s)
        if s.hasPrefix(": ") { s = s.dropFirst(2); SyslogLex.skipSpaces(&s) }
        guard let first = matchTag(s) else { return }
        s = s[first.end...]
        var app = first.name, pid = first.pid
        if pid == nil, let second = matchTag(s), second.pid != nil || app == "syslog" {
            app = second.name; pid = second.pid; s = s[second.end...]
        }
        e.appName = app
        e.procID = pid
    }

    static func matchTag(_ s: Substring) -> Tag? {
        var i = s.startIndex
        var lastSlash: Substring.Index?
        var n = 0
        while i < s.endIndex, n < 64 {
            let c = s[i]
            if c.isLetter || c.isNumber || c == "_" || c == "-" || c == "." { i = s.index(after: i); n += 1; continue }
            if c == "/" { lastSlash = i; i = s.index(after: i); n += 1; continue }
            break
        }
        guard i > s.startIndex, i < s.endIndex else { return nil }
        let nameStart = lastSlash.map { s.index(after: $0) } ?? s.startIndex
        let name = String(s[nameStart..<i])
        guard !name.isEmpty else { return nil }
        var pid: String?
        var j = i
        if s[j] == "[" {
            guard let close = s[j...].firstIndex(of: "]"), close > s.index(after: j), s[s.index(after: j)..<close].allSatisfy(\.isNumber) else { return nil }
            pid = String(s[s.index(after: j)..<close])
            j = s.index(after: close)
        }
        guard j < s.endIndex, s[j] == ":" else { return nil }
        j = s.index(after: j)
        guard j == s.endIndex || s[j] == " " else { return nil }
        while j < s.endIndex, s[j] == " " { j = s.index(after: j) }
        return Tag(name: name, pid: pid, end: j)
    }
}
