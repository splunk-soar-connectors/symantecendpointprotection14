**Unreleased**

* Validated scan types before using them in SEPM command paths and XML payloads.
* Enabled SEPM server certificate verification by default while retaining an explicit opt-out.
* Encoded connector widget values for their inline JavaScript string context.
* Encrypted cached SEPM bearer tokens before persisting connector state.
* Rejected oversized command result XML and documents containing DTD or entity declarations.
* Suppressed authentication response bodies and headers from connector debug data.
* Reattached fingerprint blocklists to their target groups on retries and no-op hash updates.
* Failed endpoint resolution when an IP address or hostname matches multiple SEPM records.
