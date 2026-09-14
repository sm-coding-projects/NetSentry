import Foundation
import NetSentryCore
import NetSentryDevTools

// nsgen — developer utility. Phase 1: send syslog samples over UDP/TCP at a given rate.
// Phase 2 adds IPFIX generation (valid + malformed datagrams, template games, exporters, bursts).

func usage() -> Never {
    print("""
    usage: nsgen syslog [--host H] [--port P] [--tcp] [--count N] [--rate R] [--style 3164|5424|netfilter|mixed]
           nsgen raw   [--host H] [--port P] [--bytes N] [--count N]
           nsgen ipfix [--host H] [--port 2055] [--scenario steady|burst|multi|gaps|missing-template|replace-template|malformed]
                       [--seconds S] [--rate flows/s] [--per-message N] [--exporters N] [--domain D] [--template-every N] [--seed S]
    """)
    exit(2)
}

var args = Array(CommandLine.arguments.dropFirst())
guard let cmd = args.first else { usage() }
args.removeFirst()
@MainActor func opt(_ name: String, _ def: String) -> String {
    if let i = args.firstIndex(of: "--\(name)"), i + 1 < args.count { return args[i + 1] }
    return def
}
if cmd == "ipfix" {
    IPFIXCommands.run(args: args, opt: opt, has: { args.contains("--\($0)") })
    exit(0)
}
let host = opt("host", "127.0.0.1")
let port = UInt16(opt("port", "5514")) ?? 5514
let count = Int(opt("count", "100")) ?? 100
let rate = Double(opt("rate", "50")) ?? 50
let tcp = args.contains("--tcp")

let sender = DatagramSender(host: host, port: port, transport: tcp ? .tcp : .udp)
guard sender.waitUntilReady() else { print("connection not ready"); exit(1) }

let start = Date()
switch cmd {
case "syslog":
    let style = opt("style", "mixed")
    for i in 0..<count {
        let line: String
        switch style {
        case "3164": line = SyslogSamples.rfc3164(seq: i)
        case "5424": line = SyslogSamples.rfc5424(seq: i)
        case "netfilter": line = SyslogSamples.netfilter(seq: i, action: i % 3 == 0 ? "D" : "A")
        default: line = [SyslogSamples.rfc3164(seq: i), SyslogSamples.rfc5424(seq: i), SyslogSamples.netfilter(seq: i)][i % 3]
        }
        let payload = Data((tcp ? line + "\n" : line).utf8)
        sender.sendBlocking(payload)
        if rate > 0 { usleep(useconds_t(1_000_000 / rate)) }
    }
case "raw":
    let n = Int(opt("bytes", "64")) ?? 64
    for _ in 0..<count {
        sender.sendBlocking(Data((0..<n).map { _ in UInt8.random(in: 0...255) }))
        if rate > 0 { usleep(useconds_t(1_000_000 / rate)) }
    }
default: usage()
}
sender.close()
let secs = Date().timeIntervalSince(start)
print("sent \(sender.sent) (failed \(sender.failed)) to \(host):\(port)/\(tcp ? "tcp" : "udp") in \(String(format: "%.2f", secs)) s")
