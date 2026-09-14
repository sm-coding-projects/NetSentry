import Foundation

/// Single place where the product identity lives. Renaming the product means changing these values
/// and the matching settings in `project.yml` (PRODUCT_NAME / BUNDLE_PREFIX).
public enum Branding {
    public static let productName = "NetSentry"
    public static let bundlePrefix = "com.netsentry"
    /// Bundle identifiers of the two processes; injectable through Info.plist (`NetSentryAppBundleID`,
    /// `NetSentryCollectorBundleID`) so each side can pin the other's identity in XPC requirements.
    public static let appBundleID = infoString("NetSentryAppBundleID") ?? "\(bundlePrefix).app"
    public static let collectorBundleID = infoString("NetSentryCollectorBundleID") ?? "\(bundlePrefix).collector"
    public static let launchAgentPlistName = "\(collectorBundleID).plist"
    /// Mach service name of the collector. Release builds prefix it with the Team ID-scoped app group
    /// (`<TEAMID>.com.netsentry.collector.xpc`) so the sandboxed dashboard may look it up without a
    /// temporary exception; the value is injected through Info.plist from the `NETSENTRY_MACH_SERVICE`
    /// build setting. See docs/distribution-constraints.md.
    public static let machServiceName = infoString("NetSentryMachService") ?? "\(bundlePrefix).collector.xpc"
    /// App group shared by dashboard and collector, injected from `NETSENTRY_APP_GROUP`.
    public static let appGroupID = infoString("NetSentryAppGroup") ?? "group.\(bundlePrefix)"
    /// Apple Team ID used in XPC code-signing requirements (`NETSENTRY_TEAM_ID`).
    public static let teamID = infoString("NetSentryTeamID") ?? "TEAMID"

    private static func infoString(_ key: String) -> String? {
        guard let v = Bundle.main.infoDictionary?[key] as? String, !v.isEmpty, !v.hasPrefix("$(") else { return nil }
        return v
    }
    public static let urlScheme = "netsentry"
    public static let storageFolderName = productName
    public static let logSubsystemPrefix = bundlePrefix
    public static let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    public static let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
}
