import Foundation
import NetSentryCore

/// Versioned wrapper for every XPC message in either direction.
public struct IPCEnvelope: Codable, Sendable {
    public static let currentSchemaVersion = 1
    public static let maxPayloadBytes = 4 * 1024 * 1024

    public var schemaVersion: Int
    public var requestID: UUID
    public var kind: String
    public var payload: Data

    public init(kind: String, payload: Data, requestID: UUID = UUID()) {
        self.schemaVersion = Self.currentSchemaVersion
        self.requestID = requestID
        self.kind = kind
        self.payload = payload
    }
}

public enum IPCError: Error, Codable, Sendable, Equatable, LocalizedError {
    case unsupportedSchema(Int)
    case unknownKind(String)
    case payloadTooLarge(Int)
    case decoding(String)
    case rejected(String)
    case notConnected
    case collectorUnavailable(String)

    public var errorDescription: String? {
        switch self {
        case .unsupportedSchema(let v): "Unsupported IPC schema version \(v)."
        case .unknownKind(let k): "Unknown IPC message kind '\(k)'."
        case .payloadTooLarge(let n): "IPC payload too large (\(n) bytes)."
        case .decoding(let m): "Could not decode IPC message: \(m)"
        case .rejected(let m): m
        case .notConnected: "Not connected to the collector."
        case .collectorUnavailable(let m): "Collector unavailable: \(m)"
        }
    }
}

/// Reply wrapper carrying either a payload or an error.
public struct IPCReply: Codable, Sendable {
    public var requestID: UUID
    public var payload: Data?
    public var error: IPCError?
    public init(requestID: UUID, payload: Data? = nil, error: IPCError? = nil) {
        self.requestID = requestID; self.payload = payload; self.error = error
    }
}

public enum IPCCoding {
    nonisolated(unsafe) private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .millisecondsSince1970
        return e
    }()
    nonisolated(unsafe) private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .millisecondsSince1970
        return d
    }()

    public static func encode<T: Encodable>(_ value: T) throws -> Data { try encoder.encode(value) }
    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do { return try decoder.decode(type, from: data) } catch { throw IPCError.decoding(String(describing: error)) }
    }

    public static func envelope<T: IPCRequest>(for request: T) throws -> Data {
        try encode(IPCEnvelope(kind: T.kind, payload: try encode(request)))
    }

    public static func validate(_ envelope: IPCEnvelope) throws {
        guard envelope.schemaVersion == IPCEnvelope.currentSchemaVersion else { throw IPCError.unsupportedSchema(envelope.schemaVersion) }
        guard envelope.payload.count <= IPCEnvelope.maxPayloadBytes else { throw IPCError.payloadTooLarge(envelope.payload.count) }
    }
}

/// A request type with a fixed `kind` and typed reply.
public protocol IPCRequest: Codable, Sendable {
    associatedtype Reply: Codable & Sendable
    static var kind: String { get }
}

/// A push message from the collector to subscribed dashboards.
public protocol IPCNotification: Codable, Sendable {
    static var kind: String { get }
}

/// Objective-C surface exported by the collector.
@objc public protocol CollectorXPCProtocol {
    func send(_ envelope: Data, reply: @escaping @Sendable (Data) -> Void)
}

/// Objective-C surface exported by the dashboard (reverse channel).
@objc public protocol CollectorClientXPCProtocol {
    func deliver(_ envelope: Data)
}
