# Requirements Refinement – Week 1

## 1. Original Scope (Capstone Part A)
In Capstone Part A, the project was defined as a general-purpose intrusion detection system aimed at monitoring server activity for suspicious behaviour. The initial scope included:
- Monitoring multiple log sources (SSH, web, firewall)
- Detecting various attack types (brute-force, port scanning, DoS)
- Generating real-time alerts

However, this scope was overly broad for an 8-week implementation timeline and lacked focus on a specific, measurable threat model.

## 2. Refined Scope (Week 1 Decision)
To ensure feasibility, depth, and alignment with assessment milestones, the scope has been refined to:

> **"SentinelNode: Secure Centralized Logging & Audit that analyses Linux authentication logs (`/var/log/auth.log`) to identify and alert on repeated failed login attempts from the same source IP within a defined time window."**

### Key Boundaries
| In Scope | Out of Scope |
|--------|--------------|
| Parsing `/var/log/auth.log` (real or synthetic) | Monitoring Windows Event Logs |
| Detecting SSH brute-force via rule-based logic (e.g., ≥5 failures in 2 minutes) | Signature-based malware detection |
| Generating structured alerts (CSV + console output) | Active blocking (e.g., iptables integration) |
| Unit and scenario-based testing | Full SIEM integration (e.g., Splunk, ELK) |
| Python-based implementation with modular design | GUI dashboard or mobile app |

## 3. Success Criteria
The MVP (by Week 3) will be considered successful if it can:
1. Parse a sample `auth.log` file and extract: timestamp, source IP, username, and outcome.
2. Identify IPs with **≥5 failed SSH login attempts within any 2-minute sliding window**.
3. Output detected events to `data/processed/alerts.csv` with fields: `timestamp`, `ip`, `failure_count`.
4. Run without errors on Ubuntu 22.04 (or WSL2) using only open-source dependencies.

## 4. Justification for Refinement
- **Feasibility**: Focusing on one log type and one attack vector ensures depth over breadth.
- **Evidence Alignment**: SSH brute-force is well-documented, with public datasets (e.g., CICIDS2017) and clear validation metrics.
- **Assessment Fit**: Matches Week 3 MVP expectations (core functionality + validation) and Week 6 hardening (false positive analysis, edge cases).
- **Security Relevance**: SSH brute-force remains a top initial access vector in real-world breaches (per Verizon DBIR 2025).

## 5. Risks and Mitigations
| Risk | Mitigation |
|------|-----------|
| No access to real `/var/log/auth.log` due to permissions | Use synthetic logs generated via `scripts/simulate_attack.py` |
| Ambiguous log formats across Linux distros | Standardise on Ubuntu 22.04 syslog format; document assumptions |
| Time constraints limiting testing depth | Prioritise core detection logic; defer alerting integrations to stretch goals |