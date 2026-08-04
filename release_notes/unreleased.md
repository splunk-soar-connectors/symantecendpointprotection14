**Unreleased**

* Normalizes endpoint hostnames while rejecting ambiguous matches before containment actions.
* Returns clean action errors for malformed fingerprint lookup failures.
* Handles contentless command status pages while retaining results from every page.
* Scopes managed fingerprint blocklists to the local SOAR installation.
* Requires local quarantine provenance or an explicit override before unquarantining endpoints.
* Binds stored SEPM credentials to the asset server URL until connector state is reset.
