# Exports and redaction

All exports are produced by `NetSentryExport` and written through a save panel with owner-only
permissions. The redaction sheet shown before every export applies one `RedactionPolicy`; the policy
summary is embedded in the file (`redaction` field / report header) so a recipient knows what was removed.

| Export | Where | Formats | Contents |
|---|---|---|---|
| Flows | Flows view → Export… | CSV, JSON | The loaded rows (current filter and pages fetched so far) |
| Events | Events view → Export… | CSV, JSON | The loaded rows |
| Alerts | Security view → Export alerts… | CSV, JSON | The alerts matching the current state/severity filter |
| Incident report | Security view → Export report… | Markdown | One alert: rule, severity, evidence, explanation, baseline, steps, notes, and its ±15 min timeline |
| Investigation bundle | Investigation view → Export bundle… | JSON (`netsentry-investigation/1`) | Every timeline entry with the full flow/event records and relations, plus the anchoring alert if any |
| Diagnostics | Collector Health → Export diagnostics… | zip | health, configuration (secrets stripped), storage status, verification, manifest usage, 7-day gaps, detection stats, system facts, 2 h of NetSentry log lines; optionally the newest raw capture and a manifest backup |
| Backup | Storage → Back up manifest… | zip | `meta.sqlite` (online backup, consistent while writing) and `collector.json` |

## Redaction policy

| Option | Effect |
|---|---|
| Hash internal addresses | Internal IPs become `ip-<12 hex>` = SHA-256(salt ‖ address) truncated. The salt is random per export, so tokens from two exports cannot be joined; within one export the same address always maps to the same token. Applies to structured fields **and** free text (messages, titles, explanations, evidence). |
| Hash external addresses | Same for public addresses. |
| Remove MAC addresses | `[mac]` placeholder (kept as a marker that a value existed). |
| Remove hostnames | `[host]` placeholder. |
| Remove raw syslog text | Raw lines omitted; parsed fields and the normalized message stay. |
| Remove usernames | `[user]` placeholder. |
| Remove analyst notes | `[note removed]`. |

Presets: **Nothing** (personal archive) and **For sharing** (internal addresses hashed, MACs, hostnames,
raw text, usernames and notes removed).

## JSON envelope (`netsentry-export/1`)

```json
{ "format": "netsentry-export/1", "product": "NetSentry", "generatedAt": "…", "kind": "flows|events|alerts",
  "redaction": "internal addresses hashed, MACs removed", "count": 2, "records": [ … ] }
```

Flow fields: `id, start, end, src, srcPort, dst, dstPort, proto, protoName, packets, bytes, direction,
service, srcClient, dstClient, dstCountry, dstASN, dstOrg, exporter, sampled`. Event fields: `id, time,
timeInferred, source, facility, severity, host, app, type, action, src, srcPort, dst, dstPort, proto, rule,
ids, idsCategory, idsSeverity, user, device, parser, status, message, raw`. Byte and packet counts are
**as exported by the gateway** (sampled when `sampled` is true); they are never scaled.

## Restoring a backup

1. Quit the dashboard and stop the collector (Settings → Background collector off, or
   `launchctl bootout gui/$UID/com.netsentry.collector`).
2. Unzip the backup; replace `<Store>/meta.sqlite` with the backup's `meta.sqlite` and delete
   `meta.sqlite-wal` and `meta.sqlite-shm` if present.
3. Start the collector again. Recovery reconciles the manifest with the Parquet files on disk: segments
   written after the backup are re-registered from their footers where possible, missing files are dropped
   from the manifest, and the result is logged under `storage`.
