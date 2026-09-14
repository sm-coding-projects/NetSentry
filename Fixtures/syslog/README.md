# Syslog fixtures

One file per message family. Lines starting with `#` are comments. Each fixture line is the exact
UDP payload (without trailing newline). Files marked *synthetic* follow public formats (RFC 3164,
RFC 5424, netfilter LOG, dnsmasq, OpenSSH, Suricata fast) and are replaced by sanitized captures
from the UCG Fiber as they arrive (docs/required-fixtures.md). Real captures are sanitized: public
addresses → 203.0.113.0/24 (TEST-NET-3), MACs → locally administered, hostnames/usernames → generic.
