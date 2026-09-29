# 🛡️ sec-audit-telemetry-cli

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Compliance Baseline](https://img.shields.io/badge/Standard-CIS%20%2F%20NIST%20Aware-orange.svg)](#)

> Automated host auditing, telemetry collection, and listening service inspector. Built to provide repeatable, machine-readable JSON assessments for system hardening and compliance logging.

---

### 📌 Core Capabilities
* **Host Telemetry:** Gathers CPU, memory, filesystem saturation, and OS build metadata.
* **Network Surface Audit:** Detects active `LISTEN` sockets, bound interfaces, and associated PID processes.
* **Privilege Validation:** Flags non-standard administrative execution contexts to mitigate elevated-privilege exploits.
* **Automated Audit Artifacts:** Exports standardized, structured UTC-timestamped JSON reports suitable for SIEM ingestion (Splunk, Elastic) or pipeline review.

---

### ⚙️️ Quickstart & Deployment

```bash
# Clone the repository
git clone [https://github.com/Gibson13/sec-audit-telemetry-cli.git](https://github.com/Gibson13/sec-audit-telemetry-cli.git)
cd sec-audit-telemetry-cli

# Install dependencies
pip install -r requirements.txt

# Run terminal stdout audit
python audit_cli.py

# Export timestamped audit report to JSON
python audit_cli.py --export
