import XCTest
@testable import NetSentryIPC

final class CodeSigningTests: XCTestCase {
    func testPinsTeamWhenTeamIDIsReal() {
        XCTAssertEqual(XPCRequirement.peer(identifier: "com.example.app", pinToTeam: true, teamID: "ABCDE12345"),
                       "anchor apple generic and identifier \"com.example.app\" and certificate leaf[subject.OU] = \"ABCDE12345\"")
    }

    func testAdhocPlaceholderFallsBackToIdentifierOnly() {
        XCTAssertEqual(XPCRequirement.peer(identifier: "com.example.app", pinToTeam: true, teamID: "TEAMID"), "identifier \"com.example.app\"")
        XCTAssertEqual(XPCRequirement.peer(identifier: "com.example.app", pinToTeam: true, teamID: ""), "identifier \"com.example.app\"")
    }

    func testUnpinnedIsIdentifierOnly() {
        XCTAssertEqual(XPCRequirement.peer(identifier: "com.example.app", pinToTeam: false, teamID: "ABCDE12345"), "identifier \"com.example.app\"")
    }
}
