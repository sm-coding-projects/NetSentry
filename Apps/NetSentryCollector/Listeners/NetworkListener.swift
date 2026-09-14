import Foundation
import Network
import NetSentryCore
import NetSentrySyslog
import os

/// Delegate through which listeners report state and hand off datagrams. Called on the listener queue.
protocol NetworkListenerDelegate: AnyObject, Sendable {
    func listener(_ listener: NetworkListener, didChangeState state: ListenerState)
    func listener(_ listener: NetworkListener, didReceive datagram: RawDatagram)
    func listener(_ listener: NetworkListener, connectionCountChanged count: Int)
}

/// One UDP or TCP listener bound to a port and optional interface, built on Network.framework.
/// Reception never waits for downstream stages: datagrams are timestamped and pushed to a SyncBoundedQueue.
final class NetworkListener: @unchecked Sendable {
    static let maxDatagram = 65_535
    static let maxTCPConnections = 64
    static let maxTCPLineBytes = 8 * 1024
    static let maxTCPBufferBytes = 1024 * 1024

    let configuration: ListenerConfiguration
    let queue = DispatchQueue(label: "\(Branding.bundlePrefix).listener", qos: .userInitiated)
    private let log = Log.logger("listener", process: "collector")
    private var listener: NWListener?
    private var connections: [ObjectIdentifier: NWConnection] = [:]
    private var tcpFramers: [ObjectIdentifier: SyslogTCPFramer] = [:]
    private weak var delegate: (any NetworkListenerDelegate)?
    private(set) var state: ListenerState = .stopped

    init(configuration: ListenerConfiguration, delegate: any NetworkListenerDelegate) {
        self.configuration = configuration
        self.delegate = delegate
    }

    func start() {
        queue.async { [self] in startOnQueue() }
    }

    func stop() {
        queue.async { [self] in
            listener?.cancel()
            listener = nil
            for (_, c) in connections { c.cancel() }
            connections.removeAll()
            tcpFramers.removeAll()
            setState(.stopped)
        }
    }

    private func setState(_ s: ListenerState) {
        state = s
        delegate?.listener(self, didChangeState: s)
    }

    private func startOnQueue() {
        setState(.starting)
        let params: NWParameters
        switch configuration.transport {
        case .udp:
            params = NWParameters.udp
        case .tcp:
            let tcp = NWProtocolTCP.Options()
            tcp.enableKeepalive = true
            tcp.keepaliveIdle = 60
            tcp.noDelay = true
            params = NWParameters(tls: nil, tcp: tcp)
        }
        params.allowLocalEndpointReuse = true
        params.acceptLocalOnly = false
        if let iface = configuration.interface, !iface.isEmpty {
            // Bind to the interface's first non-link-local address so only that interface receives.
            if let info = NetworkInterfaces.list().first(where: { $0.name == iface }), let addr = info.addresses.first {
                params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(addr), port: NWEndpoint.Port(rawValue: configuration.port)!)
            } else {
                setState(.failed("Interface \(iface) has no usable address"))
                return
            }
        }
        guard let port = NWEndpoint.Port(rawValue: configuration.port) else {
            setState(.failed("Invalid port \(configuration.port)"))
            return
        }
        do {
            let l = try NWListener(using: params, on: port)
            listener = l
            l.stateUpdateHandler = { [weak self] st in
                guard let self else { return }
                switch st {
                case .setup, .waiting: self.setState(.starting)
                case .ready: self.setState(.listening)
                case .failed(let e): self.setState(.failed(Self.describe(e)))
                case .cancelled: self.setState(.stopped)
                @unknown default: break
                }
            }
            l.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
            l.start(queue: queue)
        } catch {
            setState(.failed(Self.describe(error)))
        }
    }

    private static func describe(_ error: any Error) -> String {
        if let e = error as? NWError {
            switch e {
            case .posix(let code):
                if code == .EADDRINUSE { return "Port already in use (EADDRINUSE)" }
                if code == .EACCES { return "Permission denied binding port (EACCES)" }
                return "POSIX \(code.rawValue): \(String(cString: strerror(code.rawValue)))"
            default: return String(describing: e)
            }
        }
        return String(describing: error)
    }

    private func accept(_ conn: NWConnection) {
        let key = ObjectIdentifier(conn)
        if configuration.transport == .tcp, connections.count >= Self.maxTCPConnections {
            log.warning("Refusing TCP connection: limit reached")
            conn.cancel()
            return
        }
        connections[key] = conn
        if configuration.transport == .tcp { delegate?.listener(self, connectionCountChanged: connections.count) }
        conn.stateUpdateHandler = { [weak self, weak conn] st in
            guard let self else { return }
            switch st {
            case .failed, .cancelled:
                self.connections.removeValue(forKey: key)
                self.tcpFramers.removeValue(forKey: key)
                if self.configuration.transport == .tcp { self.delegate?.listener(self, connectionCountChanged: self.connections.count) }
            case .ready:
                if let conn { self.configuration.transport == .udp ? self.receiveDatagram(conn) : self.receiveStream(conn) }
            default: break
            }
        }
        conn.start(queue: queue)
    }

    private func remote(_ conn: NWConnection) -> (NetSentryCore.IPAddress, UInt16) {
        if case .hostPort(let host, let port) = conn.endpoint {
            let text: String
            switch host {
            case .ipv4(let a): text = "\(a)"
            case .ipv6(let a): text = "\(a)"
            case .name(let n, _): text = n
            @unknown default: text = "0.0.0.0"
            }
            var t = text
            if let pct = t.firstIndex(of: "%") { t = String(t[..<pct]) }
            return (NetSentryCore.IPAddress(t) ?? NetSentryCore.IPAddress(v4: 0), port.rawValue)
        }
        return (NetSentryCore.IPAddress(v4: 0), 0)
    }

    private func receiveDatagram(_ conn: NWConnection) {
        conn.receiveMessage { [weak self, weak conn] content, _, _, error in
            guard let self, let conn else { return }
            if let content, !content.isEmpty {
                let ts = Timestamp.now
                let (ip, port) = self.remote(conn)
                self.delegate?.listener(self, didReceive: RawDatagram(receivedAt: ts, kind: self.configuration.kind, transport: .udp,
                                                                       source: ip, sourcePort: port, localPort: self.configuration.port, payload: content))
            }
            if error == nil { self.receiveDatagram(conn) }
        }
    }

    /// TCP syslog: RFC 6587 octet-counting or LF framing via `SyslogTCPFramer`; buffers are bounded.
    private func receiveStream(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self, weak conn] content, _, isComplete, error in
            guard let self, let conn else { return }
            let key = ObjectIdentifier(conn)
            let (ip, port) = self.remote(conn)
            if let content, !content.isEmpty {
                let ts = Timestamp.now
                var framer = self.tcpFramers[key] ?? SyslogTCPFramer()
                for msg in framer.append(content) {
                    self.delegate?.listener(self, didReceive: RawDatagram(receivedAt: ts, kind: self.configuration.kind, transport: .tcp,
                                                                           source: ip, sourcePort: port, localPort: self.configuration.port, payload: msg))
                }
                self.tcpFramers[key] = framer
            }
            if isComplete || error != nil {
                if var framer = self.tcpFramers.removeValue(forKey: key), let rest = framer.flush() {
                    self.delegate?.listener(self, didReceive: RawDatagram(receivedAt: .now, kind: self.configuration.kind, transport: .tcp,
                                                                           source: ip, sourcePort: port, localPort: self.configuration.port, payload: rest))
                }
                conn.cancel()
                return
            }
            self.receiveStream(conn)
        }
    }
}
