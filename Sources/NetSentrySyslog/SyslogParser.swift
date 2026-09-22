import Foundation
import NetSentryCore

/// A family parser claims messages it recognizes and fills structured fields. Parsers are pure,
/// versioned, and registered in `ParserRegistry`. `verified` is false until a sanitized real-device
/// fixture confirms the format (docs/required-fixtures.md).
public protocol SyslogFamilyParser: Sendable {
    static var name: String { get }
    static var version: UInt16 { get }
    static var family: EventType { get }
    static var verified: Bool { get }
    static var description: String { get }
    /// True for parsers that only assign a family and extract no fields; such events stay `.partial`.
    static var classifiesOnly: Bool { get }
    /// Returns true when the parser recognized the message and populated `event`. A parser whose `family` is
    /// `.unknown` sets `event.eventType` itself.
    func parse(_ event: inout SyslogEvent) -> Bool
}

public extension SyslogFamilyParser {
    static var classifiesOnly: Bool { false }
}

/// Top-level syslog parser: header (RFC 5424 or 3164), UniFi wrapper normalization, then family parsers in
/// registry order (first claim wins), else fallback.
public struct SyslogParser: Sendable {
    public static let headerParserName = "syslog-header"
    public static let headerParserVersion: UInt16 = 1
    public static let fallbackParserName = "fallback"
    public static let fallbackParserVersion: UInt16 = 1
    public static let maxMessageBytes = 8 * 1024

    public let families: [any SyslogFamilyParser]
    public let timeZone: TimeZone

    public init(families: [any SyslogFamilyParser] = ParserRegistry.defaultParsers, timeZone: TimeZone = .current) {
        self.families = families
        self.timeZone = timeZone
    }

    public func parse(_ datagram: RawDatagram) -> SyslogEvent {
        var payload = datagram.payload
        var truncated = false
        if payload.count > Self.maxMessageBytes { payload = payload.prefix(Self.maxMessageBytes); truncated = true }
        while let last = payload.last, last == 0 || last == 0x0A || last == 0x0D { payload.removeLast() }
        let (text, lossy) = Self.decodeUTF8(payload)
        var event = SyslogEvent(receivedAt: datagram.receivedAt, sourceIP: datagram.source, transport: datagram.transport, message: text, raw: text)
        if lossy { event.rawBytes = payload; event.attributes["raw.lossyUTF8"] = "true" }
        if truncated { event.attributes["raw.truncated"] = "true" }

        var s = Substring(text)
        if s.first == "<", let close = s.firstIndex(of: ">"), close > s.index(after: s.startIndex), s.distance(from: s.startIndex, to: close) <= 4,
           let pri = Int(s[s.index(after: s.startIndex)..<close]), pri >= 0, pri <= 191 {
            event.facility = SyslogFacility(rawValue: UInt8(pri / 8)) ?? .user
            event.severity = SyslogSeverity(rawValue: UInt8(pri % 8)) ?? .informational
            s = s[s.index(after: close)...]
        } else {
            event.priorityPresent = false
        }

        if s.hasPrefix("1 ") {
            RFC5424.parse(&s, into: &event)
        } else {
            RFC3164.parse(&s, into: &event, receivedAt: datagram.receivedAt, timeZone: timeZone)
        }
        event.message = String(s)
        event.parserName = Self.headerParserName
        event.parserVersion = Self.headerParserVersion
        event.parseStatus = .partial
        UniFiDeviceTag.normalize(&event)

        for p in families where p.parse(&event) {
            let t = type(of: p)
            event.parserName = t.name
            event.parserVersion = t.version
            if t.family != .unknown { event.eventType = t.family }
            if event.parseStatus == .partial, !t.classifiesOnly { event.parseStatus = .parsed }
            return event
        }
        // Nothing recognizable (no PRI, no timestamp, no tag): keep the whole text verbatim as an unparsed event
        // rather than trusting a random first word as the hostname.
        if !event.priorityPresent && event.eventTime == nil && event.appName == nil {
            event.hostname = nil
            event.procID = nil
            event.message = text
            event.parserName = Self.fallbackParserName
            event.parserVersion = Self.fallbackParserVersion
            event.parseStatus = .unparsed
        }
        return event
    }

    static func decodeUTF8(_ data: Data) -> (String, Bool) {
        if let s = String(data: data, encoding: .utf8) { return (s, false) }
        return (String(decoding: data, as: UTF8.self), true)
    }
}

// MARK: - Shared helpers

enum SyslogLex {
    static func token(_ s: inout Substring) -> Substring? {
        while s.first == " " { s.removeFirst() }
        guard !s.isEmpty else { return nil }
        let end = s.firstIndex(of: " ") ?? s.endIndex
        let t = s[s.startIndex..<end]
        s = s[end...]
        return t
    }
    static func skipSpaces(_ s: inout Substring) { while s.first == " " { s.removeFirst() } }
}

enum RFC5424 {
    static func parse(_ s: inout Substring, into e: inout SyslogEvent) {
        e.syslogVersion = 1
        s.removeFirst(2)
        guard let ts = SyslogLex.token(&s) else { return }
        e.eventTime = ts == "-" ? nil : parseTimestamp(ts)
        if e.eventTime == nil && ts != "-" { e.attributes["time.unparsed"] = String(ts) }
        e.hostname = nilIfDash(SyslogLex.token(&s))
        e.appName = nilIfDash(SyslogLex.token(&s))
        e.procID = nilIfDash(SyslogLex.token(&s))
        e.msgID = nilIfDash(SyslogLex.token(&s))
        SyslogLex.skipSpaces(&s)
        if s.first == "-" { s.removeFirst() }
        else if s.first == "[" { e.structuredData = parseStructuredData(&s) }
        SyslogLex.skipSpaces(&s)
        if s.hasPrefix("\u{FEFF}") { s.removeFirst() }
    }

    static func nilIfDash(_ t: Substring?) -> String? { guard let t, t != "-" else { return nil }; return String(t) }

    static func parseTimestamp(_ t: Substring) -> Timestamp? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: String(t)) { return Timestamp(d) }
        f.formatOptions = [.withInternetDateTime]
        if let d = f.date(from: String(t)) { return Timestamp(d) }
        return nil
    }

    /// `[id k="v" k2="v2"][id2 ...]` with `\"`, `\]`, `\\` escapes.
    static func parseStructuredData(_ s: inout Substring) -> [String: [String: String]] {
        var out: [String: [String: String]] = [:]
        while s.first == "[" {
            s.removeFirst()
            guard let idEnd = s.firstIndex(where: { $0 == " " || $0 == "]" }) else { break }
            let id = String(s[s.startIndex..<idEnd])
            s = s[idEnd...]
            var params: [String: String] = [:]
            while true {
                SyslogLex.skipSpaces(&s)
                if s.first == "]" { s.removeFirst(); break }
                guard let eq = s.firstIndex(of: "="), s.index(after: eq) < s.endIndex, s[s.index(after: eq)] == "\"" else { break }
                let key = String(s[s.startIndex..<eq])
                var i = s.index(eq, offsetBy: 2)
                var value = ""
                var closed = false
                while i < s.endIndex {
                    let c = s[i]
                    if c == "\\", s.index(after: i) < s.endIndex { value.append(s[s.index(after: i)]); i = s.index(i, offsetBy: 2); continue }
                    if c == "\"" { closed = true; i = s.index(after: i); break }
                    value.append(c); i = s.index(after: i)
                }
                params[key] = value
                s = s[i...]
                if !closed { break }
            }
            out[id] = params
            if s.first != "[" { break }
        }
        return out
    }
}

enum RFC3164 {
    private static let months = ["Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12]

    static func parse(_ s: inout Substring, into e: inout SyslogEvent, receivedAt: Timestamp, timeZone: TimeZone) {
        e.syslogVersion = 0
        SyslogLex.skipSpaces(&s)
        if let t = parseBSDTimestamp(&s, receivedAt: receivedAt, timeZone: timeZone) {
            e.eventTime = t
            e.timeInferred = true
        } else if let first = s.split(separator: " ", maxSplits: 1).first, first.count >= 19, first[first.index(first.startIndex, offsetBy: 4)] == "-",
                  let iso = RFC5424.parseTimestamp(first) {
            e.eventTime = iso
            s = s[first.endIndex...]
        }
        SyslogLex.skipSpaces(&s)
        let save = s
        if let host = SyslogLex.token(&s), !host.contains(":"), !host.contains("["), !host.isEmpty {
            e.hostname = String(host)
        } else {
            s = save
        }
        SyslogLex.skipSpaces(&s)
        if let colon = s.firstIndex(of: ":"), s.distance(from: s.startIndex, to: colon) <= 48 {
            var tag = s[s.startIndex..<colon]
            if tag.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." || $0 == "/" || $0 == "[" || $0 == "]" }) {
                if let br = tag.firstIndex(of: "["), tag.last == "]" {
                    e.procID = String(tag[tag.index(after: br)..<tag.index(before: tag.endIndex)])
                    tag = tag[tag.startIndex..<br]
                }
                if !tag.isEmpty { e.appName = String(tag) }
                s = s[s.index(after: colon)...]
                SyslogLex.skipSpaces(&s)
            }
        }
    }

    /// Interprets "Sep 10 19:35:23" in the given zone, picking the year closest to `receivedAt`.
    static func parseBSDTimestamp(_ s: inout Substring, receivedAt: Timestamp, timeZone: TimeZone) -> Timestamp? {
        guard s.count >= 15 else { return nil }
        let mon = String(s.prefix(3))
        guard let month = months[mon], s[s.index(s.startIndex, offsetBy: 3)] == " " else { return nil }
        var i = s.index(s.startIndex, offsetBy: 4)
        var dayText = ""
        while i < s.endIndex, s[i] == " " { i = s.index(after: i) }
        while i < s.endIndex, s[i].isNumber { dayText.append(s[i]); i = s.index(after: i) }
        guard let day = Int(dayText), day >= 1, day <= 31, i < s.endIndex, s[i] == " " else { return nil }
        i = s.index(after: i)
        guard s.distance(from: i, to: s.endIndex) >= 8 else { return nil }
        let timePart = s[i...].prefix(8)
        let parts = timePart.split(separator: ":")
        guard parts.count == 3, let h = Int(parts[0]), let m = Int(parts[1]), let sec = Int(parts[2]), h < 24, m < 60, sec < 61 else { return nil }
        i = s.index(i, offsetBy: 8)
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = timeZone
        let nowYear = cal.component(.year, from: receivedAt.date)
        var best: Date?
        for year in [nowYear, nowYear - 1, nowYear + 1] {
            var dc = DateComponents(); dc.year = year; dc.month = month; dc.day = day; dc.hour = h; dc.minute = m; dc.second = sec
            guard let d = cal.date(from: dc) else { continue }
            if best == nil || abs(d.timeIntervalSince(receivedAt.date)) < abs(best!.timeIntervalSince(receivedAt.date)) { best = d }
        }
        guard let date = best else { return nil }
        s = s[i...]
        return Timestamp(date)
    }
}

/// RFC 6587 framing for TCP streams: octet counting ("123 <34>...") or non-transparent (LF-terminated).
public struct SyslogTCPFramer: Sendable {
    public static let maxFrame = SyslogParser.maxMessageBytes
    private var buffer = Data()
    public init() {}

    public mutating func append(_ data: Data) -> [Data] {
        buffer.append(data)
        var out: [Data] = []
        while !buffer.isEmpty {
            if let first = buffer.first, first >= 0x30, first <= 0x39, let sp = buffer.firstIndex(of: 0x20), sp - buffer.startIndex <= 6,
               let len = Int(String(decoding: buffer[buffer.startIndex..<sp], as: UTF8.self)), len > 0 {
                let start = sp + 1
                guard buffer.endIndex - start >= len else { break }
                out.append(Data(buffer[start..<start + len]))
                buffer = Data(buffer[(start + len)...])
                continue
            }
            guard let nl = buffer.firstIndex(of: 0x0A) else {
                if buffer.count > Self.maxFrame * 2 { out.append(Data(buffer.prefix(Self.maxFrame))); buffer.removeAll() }
                break
            }
            var line = buffer[buffer.startIndex..<nl]
            if line.last == 0x0D { line = line.dropLast() }
            if !line.isEmpty { out.append(Data(line)) }
            buffer = Data(buffer[(nl + 1)...])
        }
        return out
    }

    public mutating func flush() -> Data? {
        defer { buffer.removeAll() }
        return buffer.isEmpty ? nil : buffer
    }
}
