import Foundation
import NetSentryCore

/// Code-signing requirement strings used on both ends of the XPC connection.
/// The requirement language has no wildcard for `identifier`, so each side pins the other's exact
/// bundle identifier; release builds additionally pin the Team ID.
public enum XPCRequirement {
    public static func peer(identifier: String, pinToTeam: Bool) -> String {
        if pinToTeam {
            return "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(Branding.teamID)\""
        }
        return "identifier \"\(identifier)\""
    }
    /// Requirement the dashboard applies to the collector.
    public static func collector(pinToTeam: Bool) -> String { peer(identifier: Branding.collectorBundleID, pinToTeam: pinToTeam) }
    /// Requirement the collector applies to the dashboard.
    public static func dashboard(pinToTeam: Bool) -> String { peer(identifier: Branding.appBundleID, pinToTeam: pinToTeam) }
}
