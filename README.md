# NetSentry

Privacy-first local network observability and security analytics for a UniFi Cloud Gateway Fiber.
Receives IPFIX (NetFlow v10) and syslog on a Mac, stores them within a bounded budget, and provides
investigation, correlation, and explainable detections — all locally.

Status: **Phases 0–6 delivered**; see `docs/delivery-plan.md` for what remains on the roadmap. See `docs/delivery-plan.md`.

Build: `./Scripts/generate-project.sh && xcodebuild -project NetSentry.xcodeproj -scheme NetSentry build`
(see `docs/developer-setup.md`). Tests: `swift test`.

| Document | Purpose |
|---|---|
| `docs/adr/ADR-001-architecture.md` | Architecture decisions and rationale |
| `docs/modules-and-repository.md` | Module boundaries and repository layout |
| `docs/ipc-contracts.md` | Dashboard ⇄ collector XPC contract |
| `docs/schemas/` | Flow, event, entity, alert, segment schemas and SQLite DDL |
| `docs/storage-lifecycle.md` | Budget, segments, compaction, retention stages, recovery |
| `docs/threat-model.md` | Assets, trust boundaries, mitigations |
| `docs/performance-targets.md` | Measurable targets and query strategy |
| `docs/required-fixtures.md` | Real UCG Fiber samples and settings needed |
| `docs/distribution-constraints.md` | Entitlements, signing, sandbox, notarization |
| `docs/delivery-plan.md` | Phases, risks, open decisions |
| `docs/release.md` | Signing, notarization, release checklist |
| `docs/known-limitations.md` | What it does not do |
| `docs/roadmap.md` | Ordered next steps |
| `docs/exports.md` | Export formats and redaction |
| `docs/performance-results.md` | Measured benchmark results |
| `docs/adr/ADR-002-sandboxing.md` | Why neither process is sandboxed in v1 |
| `docs/developer-setup.md` | Build, tools, logs, bring-up gotchas |
| `docs/unifi-configuration.md` | Gateway settings and what the UCG Fiber actually exports |
