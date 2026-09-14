import Foundation
import Network
import NetSentryCore

/// Minimal UDP/TCP sender for development tooling and integration tests.
public final class DatagramSender: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "nsgen.sender")
    private let ready = DispatchSemaphore(value: 0)
    public private(set) var sent: UInt64 = 0
    public private(set) var failed: UInt64 = 0

    public init(host: String, port: UInt16, transport: Transport = .udp) {
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!)
        connection = NWConnection(to: endpoint, using: transport == .udp ? .udp : .tcp)
        connection.stateUpdateHandler = { [ready] st in
            if case .ready = st { ready.signal() }
            if case .failed = st { ready.signal() }
        }
        connection.start(queue: queue)
    }

    public func waitUntilReady(timeout: TimeInterval = 5) -> Bool {
        ready.wait(timeout: .now() + timeout) == .success && connection.state == .ready
    }

    public func send(_ data: Data) async {
        await withCheckedContinuation { cont in
            connection.send(content: data, completion: .contentProcessed { [weak self] err in
                if err == nil { self?.sent += 1 } else { self?.failed += 1 }
                cont.resume()
            })
        }
    }

    /// Synchronous send for command-line tools (must not be called from the main actor with pending tasks).
    public func sendBlocking(_ data: Data) {
        let sem = DispatchSemaphore(value: 0)
        connection.send(content: data, completion: .contentProcessed { [weak self] err in
            if err == nil { self?.sent += 1 } else { self?.failed += 1 }
            sem.signal()
        })
        _ = sem.wait(timeout: .now() + 5)
    }

    public func close() { connection.cancel() }
}

/// Generic RFC 3164 / RFC 5424 sample lines for exercising the receive path. These are *not* UniFi
/// formats; UniFi families come from sanitized real captures (docs/required-fixtures.md).
public enum SyslogSamples {
    public static func rfc3164(seq: Int, host: String = "gateway", app: String = "kernel") -> String {
        let f = DateFormatter(); f.dateFormat = "MMM d HH:mm:ss"; f.locale = Locale(identifier: "en_US_POSIX")
        return "<14>\(f.string(from: Date())) \(host) \(app): sample message \(seq)"
    }
    public static func rfc5424(seq: Int, host: String = "gateway", app: String = "netsentry-gen") -> String {
        let ts = ISO8601DateFormatter().string(from: Date())
        return "<134>1 \(ts) \(host) \(app) \(ProcessInfo.processInfo.processIdentifier) ID\(seq) [gen@32473 seq=\"\(seq)\"] sample structured message \(seq)"
    }
    /// Linux netfilter LOG-style line (public kernel format) with an opaque bracketed prefix.
    public static func netfilter(seq: Int, action: String = "D") -> String {
        let f = DateFormatter(); f.dateFormat = "MMM d HH:mm:ss"; f.locale = Locale(identifier: "en_US_POSIX")
        let src = "192.168.1.\(10 + seq % 40)", dst = "203.0.113.\(1 + seq % 200)"
        return "<4>\(f.string(from: Date())) gateway kernel: [WAN_OUT-\(action)-\(2000 + seq % 5)]IN=br0 OUT=eth4 MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=\(src) DST=\(dst) LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=\(seq) DF PROTO=TCP SPT=\(40000 + seq % 20000) DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0"
    }
}
