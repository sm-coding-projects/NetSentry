import Foundation
import NetSentryCore
import NetSentryIPC
import os

/// XPC client for the collector's Mach service with automatic reconnection and typed requests.
final class CollectorClient: NSObject, CollectorClientXPCProtocol, @unchecked Sendable {
    enum ConnectionState: Equatable { case disconnected, connecting, connected }

    private let log = Log.logger("xpc", process: "app")
    private let lock = NSLock()
    private var connection: NSXPCConnection?
    private(set) var state: ConnectionState = .disconnected
    private var continuation: AsyncStream<IPCEnvelope>.Continuation?
    let notifications: AsyncStream<IPCEnvelope>
    var onStateChange: (@Sendable (ConnectionState) -> Void)?

    override init() {
        var cont: AsyncStream<IPCEnvelope>.Continuation?
        notifications = AsyncStream(bufferingPolicy: .bufferingNewest(256)) { cont = $0 }
        continuation = cont
        super.init()
    }

    private func setState(_ s: ConnectionState) {
        state = s
        onStateChange?(s)
    }

    private func currentConnection() -> NSXPCConnection {
        lock.lock(); defer { lock.unlock() }
        if let c = connection { return c }
        setState(.connecting)
        let c = NSXPCConnection(machServiceName: Branding.machServiceName, options: [])
        #if DEBUG
        c.setCodeSigningRequirement(XPCRequirement.collector(pinToTeam: false))
        #else
        c.setCodeSigningRequirement(XPCRequirement.collector(pinToTeam: true))
        #endif
        c.remoteObjectInterface = NSXPCInterface(with: CollectorXPCProtocol.self)
        c.exportedInterface = NSXPCInterface(with: CollectorClientXPCProtocol.self)
        c.exportedObject = self
        c.invalidationHandler = { [weak self] in self?.dropConnection(reason: "invalidated") }
        c.interruptionHandler = { [weak self] in self?.dropConnection(reason: "interrupted") }
        c.resume()
        connection = c
        return c
    }

    private func dropConnection(reason: String) {
        lock.lock()
        connection?.invalidate()
        connection = nil
        lock.unlock()
        log.info("Collector connection \(reason, privacy: .public)")
        setState(.disconnected)
    }

    func disconnect() { dropConnection(reason: "closed by app") }

    /// Sends a typed request. Throws `IPCError.collectorUnavailable` when the agent is not reachable.
    func request<R: IPCRequest>(_ req: R, timeout: Duration = .seconds(10)) async throws -> R.Reply {
        let data = try IPCCoding.envelope(for: req)
        let conn = currentConnection()
        log.info("request \(R.kind, privacy: .public) (\(data.count) bytes)")
        let reply = try await sendEnvelope(data, over: conn, timeout: timeout)
        log.info("reply for \(R.kind, privacy: .public): \(reply.count) bytes")
        setState(.connected)
        let decoded = try IPCCoding.decode(IPCReply.self, from: reply)
        if let e = decoded.error { throw e }
        guard let payload = decoded.payload else { throw IPCError.decoding("empty reply") }
        return try IPCCoding.decode(R.Reply.self, from: payload)
    }

    /// Sends one envelope with a hard timeout. A launchd job stuck in a spawn loop never replies and
    /// never errors, so the timer is the only way out; whichever of reply/error/timeout comes first wins.
    private func sendEnvelope(_ data: Data, over conn: NSXPCConnection, timeout: Duration) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            let once = OnceResumer(cont)
            let log = self.log
            DispatchQueue.global().asyncAfter(deadline: .now() + .microseconds(Int(timeout.microsecondsValue))) {
                log.info("xpc timeout fired")
                once.finish(.failure(IPCError.collectorUnavailable("no reply within \(timeout)")))
            }
            let proxy = conn.remoteObjectProxyWithErrorHandler { error in
                log.info("xpc error handler: \(error.localizedDescription, privacy: .public)")
                once.finish(.failure(IPCError.collectorUnavailable(error.localizedDescription)))
            }
            guard let p = proxy as? CollectorXPCProtocol else { once.finish(.failure(IPCError.notConnected)); return }
            log.info("xpc send")
            p.send(data) { replyData in log.info("xpc reply"); once.finish(.success(replyData)) }
        }
    }

    // Reverse channel
    func deliver(_ envelopeData: Data) {
        guard let env = try? IPCCoding.decode(IPCEnvelope.self, from: envelopeData), (try? IPCCoding.validate(env)) != nil else { return }
        continuation?.yield(env)
    }
}


/// Resumes a continuation exactly once from whichever callback fires first (reply, XPC error, or timer).
private final class OnceResumer: @unchecked Sendable {
    private let lock = OSAllocatedUnfairLock(initialState: false)
    private let continuation: CheckedContinuation<Data, any Error>
    init(_ c: CheckedContinuation<Data, any Error>) { continuation = c }
    func finish(_ r: Result<Data, any Error>) {
        if lock.withLock({ let was = $0; $0 = true; return !was }) { continuation.resume(with: r) }
    }
}
