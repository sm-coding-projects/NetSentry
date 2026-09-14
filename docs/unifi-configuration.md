# Configuring the UniFi Cloud Gateway Fiber for NetSentry

Verified against a UCG Fiber on 2026-09-10 (UniFi Network application version to be recorded).

## 1. NetFlow (IPFIX)

UniFi Network → **Settings › CyberSecure › Traffic Logging › NetFlow**.

| Field | Value |
|---|---|
| Server / destination | the Mac's LAN address (setup wizard shows it; reserve it in DHCP or make it static) |
| Port | **2055** (UniFi's default; NetSentry listens on 2055 and 4739 by default) |
| Version | IPFIX. What the UCG Fiber sends is IPFIX (NetFlow v10): observed message version 10, observation domain 0 |
| Sampling | the gateway exports **sampled** flows; NetSentry reads the rate from the exporter's options template (observed 1:512) and shows it on every flow |

What the gateway exports (observed):

* Data template 264 (IPv4, 21 elements): src/dst IPv4, next hop, ipVersion, ports, TCP flags, in/out
  interface index, packet and octet counts (32-bit), flowStart/EndMilliseconds, protocol, ToS,
  flowEndReason, dst/src MAC, ethernetType, flowDirection, selectorId. Template 265 adds tcpOptions.
* Options templates: 256 (systemInitTimeMilliseconds, observationDomainName), 257 (sampling
  selector: algorithm, size, population), 258 (interface index → name/description), 260 (exporter
  statistics), 261 (selector statistics).
* Templates are refreshed every few messages; data for a template can arrive before the template
  after a restart, which NetSentry buffers and decodes once the template appears.
* Sequence numbers count data records (RFC 7011), which NetSentry uses to detect loss.

## 2. Remote syslog

UniFi Network → **Settings › System › Advanced › Remote Logging** (older releases) or
**Settings › CyberSecure › Traffic Logging › Syslog** (newer releases; confirm on your version).

| Field | Value |
|---|---|
| Server | the Mac's LAN address |
| Port | **5514** (UDP). Port 514 is privileged on macOS and is not supported by NetSentry v1 |
| Protocol | UDP (TCP optional, enable the TCP listener in NetSentry Settings) |
| Contents | enable everything available: firewall/traffic logs, IDS/IPS (CyberSecure), system, client, device logs |
| Firewall rules | logging is per rule/policy: enable **Log** on the rules you want to see |

## 3. Verify

NetSentry › Collector Health shows the listener state, last packet time and the exporter with its
template count; Live Activity shows decoded flows within seconds. The setup wizard (Phase 6) runs
these checks automatically.

## Known gaps (to confirm with captures)

* The exact syslog line formats for firewall, IDS/IPS, DHCP, DNS, VPN and authentication events
  are implemented from the public upstream formats (netfilter LOG, Suricata fast, dnsmasq, OpenSSH)
  and are marked *unverified* in the parser registry until real samples are captured.
