import XCTest

/// Walks every sidebar section of the running dashboard and writes a PNG per section to
/// `$NETSENTRY_SCREENSHOT_DIR` (defaults to /tmp/netsentry-screenshots). Used for release QA and docs;
/// the assertions are deliberately light so the suite doubles as a smoke test that each view renders.
final class ScreenshotTests: XCTestCase {
    override func setUpWithError() throws { continueAfterFailure = true }

    /// A directory this process may actually write to. The XCUITest runner is launched by
    /// testmanagerd under a sandbox that denies writes outside its own container, so a configured
    /// path (or /tmp) can fail with EPERM; fall back to the runner's temp dir in that case.
    private func writableScreenshotDir() -> URL {
        let configured = ProcessInfo.processInfo.environment["NETSENTRY_SCREENSHOT_DIR"].map { URL(fileURLWithPath: $0) }
        let fallback = URL(fileURLWithPath: NSTemporaryDirectory()).appending(path: "netsentry-screenshots")
        for candidate in [configured, fallback].compactMap({ $0 }) {
            try? FileManager.default.createDirectory(at: candidate, withIntermediateDirectories: true)
            let probe = candidate.appending(path: ".probe")
            if (try? Data().write(to: probe)) != nil { try? FileManager.default.removeItem(at: probe); return candidate }
        }
        return fallback
    }

    func testEverySectionRendersAndIsCaptured() throws {
        let dir = writableScreenshotDir()
        print("NETSENTRY_SHOTS_DIR=\(dir.path)")
        let app = XCUIApplication()
        app.launchArguments = ["--skip-wizard"]
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20), "main window")
        let sections = ["Overview", "Live Activity", "Clients", "Flows", "Events", "Security", "Investigation", "Storage", "Collector Health", "Settings"]
        for name in sections {
            let row = app.outlines.firstMatch.staticTexts[name].firstMatch.exists ? app.outlines.firstMatch.staticTexts[name].firstMatch : app.staticTexts[name].firstMatch
            XCTAssertTrue(row.waitForExistence(timeout: 5), "sidebar row \(name)")
            row.click()
            sleep(2)
            let shot = app.windows.firstMatch.screenshot()
            let attachment = XCTAttachment(screenshot: shot); attachment.name = name; attachment.lifetime = .keepAlways
            add(attachment)
            let file = dir.appending(path: name.lowercased().replacingOccurrences(of: " ", with: "-") + ".png")
            try? shot.pngRepresentation.write(to: file)
        }
        // The wizard, on demand.
        app.terminate()
        app.launchArguments = ["--show-wizard"]
        app.launch()
        XCTAssertTrue(app.sheets.firstMatch.waitForExistence(timeout: 20) || app.staticTexts["Welcome to NetSentry"].waitForExistence(timeout: 5), "wizard")
        sleep(1)
        let wiz = app.windows.firstMatch.screenshot()
        let wizAttachment = XCTAttachment(screenshot: wiz); wizAttachment.name = "Setup Wizard"; wizAttachment.lifetime = .keepAlways
        add(wizAttachment)
        try? wiz.pngRepresentation.write(to: dir.appending(path: "setup-wizard.png"))
    }
    /// The right-hand detail pane stays collapsed until a row is selected, and closes again from its button.
    func testDetailPaneOpensOnlyForSelection() throws {
        let app = XCUIApplication()
        app.launchArguments = ["--skip-wizard"]
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20), "main window")
        for (name, table) in [("Live Activity", "Live activity table"), ("Flows", "Flows table"), ("Events", "Events table")] {
            app.staticTexts[name].firstMatch.click()
            sleep(3)
            let close = app.buttons["Close details"].firstMatch
            XCTAssertFalse(close.exists, "\(name): pane hidden with no selection")
            let row = app.outlines[table].outlineRows.firstMatch
            guard row.waitForExistence(timeout: 20) else { print("\(name): no rows to select, skipping"); continue }
            if name == "Live Activity" { app.buttons["Pause"].firstMatch.click() }   // keep the row under the pointer
            row.cells.firstMatch.click()
            XCTAssertTrue(close.waitForExistence(timeout: 5), "\(name): pane opens on selection")
            save(app, "\(name.lowercased().replacingOccurrences(of: " ", with: "-"))-selected")
            close.click()
            sleep(1)
            XCTAssertFalse(app.buttons["Close details"].firstMatch.exists, "\(name): pane closes")
            if name == "Live Activity" { app.buttons["Resume"].firstMatch.click() }
        }
    }

    /// ⌘+ / ⌘− / ⌘0 change the size of the app's text (the sidebar keeps the system sidebar size).
    func testTextSizeShortcuts() throws {
        let app = XCUIApplication()
        app.launchArguments = ["--skip-wizard"]
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20), "main window")
        app.typeKey("0", modifierFlags: .command)
        app.staticTexts["Flows"].firstMatch.click()
        let cell = app.outlines["Flows table"].outlineRows.firstMatch.staticTexts.firstMatch
        guard cell.waitForExistence(timeout: 20) else { throw XCTSkip("no flows to measure") }
        sleep(1)
        let base = cell.frame.height
        save(app, "text-size-100-flows")
        app.typeKey("+", modifierFlags: .command)
        app.typeKey("=", modifierFlags: .command)     // ⌘= is the unshifted ⌘+ key on most layouts
        sleep(1)
        let bigger = cell.frame.height
        save(app, "text-size-130-flows")
        XCTAssertGreaterThan(bigger, base * 1.15, "⌘+ enlarges text (\(base) → \(bigger))")
        app.typeKey("-", modifierFlags: .command)
        sleep(1)
        XCTAssertLessThan(cell.frame.height, bigger, "⌘− shrinks text")
        app.typeKey("0", modifierFlags: .command)
        sleep(1)
        XCTAssertEqual(cell.frame.height, base, accuracy: 1, "⌘0 restores actual size")
    }

    private func save(_ app: XCUIApplication, _ name: String) {
        let shot = app.windows.firstMatch.screenshot()
        let attachment = XCTAttachment(screenshot: shot); attachment.name = name; attachment.lifetime = .keepAlways
        add(attachment)
        try? shot.pngRepresentation.write(to: writableScreenshotDir().appending(path: name + ".png"))
    }
}
