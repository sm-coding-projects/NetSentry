import AppKit
// Usage: swift scripts/render-app-icon.swift Apps/Shared/AppIcon.xcassets/AppIcon.appiconset /tmp/icon-preview.png

// NetSentry app icon: macOS rounded square, deep-blue gradient, a white shield ("sentry") holding a small
// network graph (hub + three nodes) with a sentinel ring around the hub. Drawn as vectors in a 1024-unit
// space and rendered natively at every size so small sizes stay crisp.

let outDir = CommandLine.arguments[1]
let previewPath = CommandLine.arguments[2]

func rgb(_ hex: UInt32, _ a: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255, blue: CGFloat(hex & 0xff) / 255, alpha: a)
}

func draw(size s: CGFloat) {
    let u = s / 1024
    let ctx = NSGraphicsContext.current!.cgContext
    ctx.setShouldAntialias(true)
    ctx.interpolationQuality = .high

    // Rounded square (Apple's macOS grid: 824 pt square inside 1024, ~22% corner radius).
    let inset = 100 * u
    let square = NSRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let radius = 185 * u
    let bg = NSBezierPath(roundedRect: square, xRadius: radius, yRadius: radius)

    if s >= 64 {
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -12 * u), blur: 28 * u, color: NSColor.black.withAlphaComponent(0.38).cgColor)
        rgb(0x0B2140).setFill(); bg.fill()
        ctx.restoreGState()
    }
    ctx.saveGState()
    bg.addClip()
    NSGradient(colorsAndLocations: (rgb(0x1E5A9C), 0.0), (rgb(0x123C6E), 0.55), (rgb(0x07182F), 1.0))!
        .draw(in: square, angle: -90)
    // Soft highlight in the upper part.
    NSGradient(starting: NSColor.white.withAlphaComponent(0.16), ending: NSColor.white.withAlphaComponent(0))!
        .draw(fromCenter: NSPoint(x: s * 0.5, y: s * 0.86), radius: 0, toCenter: NSPoint(x: s * 0.5, y: s * 0.86), radius: 620 * u, options: [])
    ctx.restoreGState()

    // Shield outline. Coordinates in the 1024 space, y up.
    func P(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: x * u, y: y * u) }
    let shield = NSBezierPath()
    shield.move(to: P(512, 796))
    shield.curve(to: P(300, 742), controlPoint1: P(440, 796), controlPoint2: P(360, 770))
    shield.line(to: P(300, 540))
    shield.curve(to: P(512, 226), controlPoint1: P(300, 400), controlPoint2: P(400, 290))
    shield.curve(to: P(724, 540), controlPoint1: P(624, 290), controlPoint2: P(724, 400))
    shield.line(to: P(724, 742))
    shield.curve(to: P(512, 796), controlPoint1: P(664, 770), controlPoint2: P(584, 796))
    shield.close()
    shield.lineJoinStyle = .round

    NSColor.white.withAlphaComponent(0.10).setFill(); shield.fill()
    let strokeW = max(34 * u, s >= 32 ? 2.0 : 1.5)
    shield.lineWidth = strokeW
    NSColor.white.withAlphaComponent(0.96).setStroke(); shield.stroke()

    // Network graph inside the shield.
    let hub = P(512, 536)
    let nodes = [P(392, 646), P(632, 646), P(512, 396)]
    let mint = rgb(0x3DDC97)

    let link = NSBezierPath()
    for n in nodes { link.move(to: hub); link.line(to: n) }
    link.lineWidth = max(20 * u, 1.2)
    link.lineCapStyle = .round
    NSColor.white.withAlphaComponent(0.85).setStroke(); link.stroke()

    // Sentinel ring around the hub (fades at small sizes where it would smear).
    if s >= 48 {
        let ring = NSBezierPath(ovalIn: NSRect(x: hub.x - 96 * u, y: hub.y - 96 * u, width: 192 * u, height: 192 * u))
        ring.lineWidth = 12 * u
        mint.withAlphaComponent(0.55).setStroke(); ring.stroke()
    }
    for n in nodes {
        let r = max(34 * u, 1.6)
        let dot = NSBezierPath(ovalIn: NSRect(x: n.x - r, y: n.y - r, width: 2 * r, height: 2 * r))
        NSColor.white.setFill(); dot.fill()
    }
    let hr = max(48 * u, 2.2)
    let hubDot = NSBezierPath(ovalIn: NSRect(x: hub.x - hr, y: hub.y - hr, width: 2 * hr, height: 2 * hr))
    mint.setFill(); hubDot.fill()
    if s >= 128 {
        hubDot.lineWidth = 10 * u
        NSColor.white.withAlphaComponent(0.9).setStroke(); hubDot.stroke()
    }
}

func render(px: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                               hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: px, height: px)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    draw(size: CGFloat(px))
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

// (point size, scale) pairs required by a macOS AppIcon set.
let entries: [(Int, Int)] = [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1), (128, 2), (256, 1), (256, 2), (512, 1), (512, 2)]
var images: [[String: String]] = []
for (pt, scale) in entries {
    let name = "icon_\(pt)x\(pt)@\(scale)x.png"
    try! render(px: pt * scale).write(to: URL(fileURLWithPath: outDir).appendingPathComponent(name))
    images.append(["size": "\(pt)x\(pt)", "idiom": "mac", "filename": name, "scale": "\(scale)x"])
}
let contents: [String: Any] = ["images": images, "info": ["version": 1, "author": "xcode"]]
try! JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: outDir).appendingPathComponent("Contents.json"))
try! render(px: 1024).write(to: URL(fileURLWithPath: previewPath))
print("rendered \(entries.count) sizes")
