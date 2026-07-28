# Enterprise MITRE ATT&CK Mapping Lab

**Building, detecting and improving a Windows detection engineering lab with Wazuh**

A self-contained, isolated detection engineering lab built on VMware Workstation Pro to practise real MITRE ATT&CK technique mapping: simulating attacker behaviour, capturing it with Sysmon, detecting it with Wazuh, and tuning the detections that don't hold up.

This is not a walkthrough of a tutorial. It documents what actually happened while building it, including the mistakes, the rebuilds, and one genuinely confirmed false positive that was root-caused and fixed with a custom detection rule.

---

## Overview

| | |
|---|---|
| **Platform** | VMware Workstation Pro |
| **Attacker** | Kali Linux 2026.1 |
| **Target** | Windows 11 Pro + Sysmon (SwiftOnSecurity config) |
| **SIEM** | Wazuh 4.14.6 (indexer, manager, dashboard, all-in-one) |
| **Framework** | MITRE ATT&CK Enterprise Matrix |
| **Author** | IBNOUSOUFYANE Ayman |

## Architecture

Three virtual machines on a single dedicated, isolated Host-only network (`VMnet2`, `192.168.50.0/24`), with no route to the physical LAN. A separate NAT adapter exists on every machine but stays disconnected outside of patch windows.

```
                    VMware Workstation Host
   ┌──────────────────────────────────────────────────┐
   │   Isolated Lab Network — VMnet2 (192.168.50.0/24) │
   │                                                    │
   │   Kali Linux        Windows 11 + Sysmon            │
   │   192.168.50.20      192.168.50.10                 │
   │   (Attacker)          (Target)                     │
   │                                                    │
   │   Ubuntu Server + Wazuh                            │
   │   192.168.50.30                                    │
   │   (Indexer / Manager / Dashboard)                  │
   └──────────────────────────────────────────────────┘
                    │  (manual, temporary)
              NAT (VMnet8) ── Internet (updates only)
```

## What this project actually demonstrates

Rather than a checklist of techniques run against a passive SIEM, this lab treats detection as something to be verified, not assumed:

- **Built and correctly isolated** a 3-VM lab network, including diagnosing and fixing a legacy `ifupdown` / NetworkManager conflict and an undersized LVM volume that silently broke a Wazuh install.
- **Instrumented Windows 11** with Sysmon using a proven community configuration, and confirmed the full pipeline from Sysmon → Wazuh agent → manager → indexer → dashboard end to end.
- **Simulated 5 attack scenarios** across Discovery, Execution, Persistence and Privilege Escalation, and evaluated exactly how well Wazuh's default ruleset detected each one, not just whether it did.
- **Found and root-caused a real false positive** (rule 92213, mistagged as T1105 Ingress Tool Transfer, actually firing on PowerShell's own internal script-policy artefact) and fixed it with a scoped custom rule, fully debugged and verified against live traffic.
- **Confirmed a genuine detection gap** (scheduled task creation via `schtasks.exe` is not covered by Wazuh's default ruleset at all) using hard evidence from the manager's own archive logs, rather than assuming.

## Findings summary

| Technique | ATT&CK ID | Detected? | Rule(s) |
|---|---|---|---|
| System Owner/User Discovery | T1033 | Generic only | 92031 / 92033 |
| System Information Discovery | T1082 | Generic only | 92031 / 92033 |
| Network Config Discovery | T1016 | Generic only | 92031 / 92033 |
| Local Account Discovery | T1087.001 | Generic only | 92031 / 92033 |
| File Deletion | T1070.004 | Yes, specific | 92021 |
| Ingress Tool Transfer (false positive) | T1105 | False positive, tuned | 92213 → 100213 |
| Obfuscated Files, Encoded PowerShell | T1027 / T1059.001 | Yes, specific | 92057 |
| Create Local Account | T1136.001 | Yes, specific | 60109 |
| Account Manipulation | T1098 / T1078.003 | Yes, high confidence | 60154 |
| Local Groups Discovery | T1069.001 | Yes, specific | 92039 |
| Scheduled Task | T1053.005 | **Not detected**, confirmed gap | none |

Full write-up, root cause analysis and screenshots for every row above are in the report.

## Repository structure

```
enterprise-mitre-attack-lab/
├── docs/
│   ├── Phase-01-Environment-Setup/
│   ├── Phase-02-Logging-Sysmon/
│   ├── Phase-03-Wazuh-Deployment/
│   ├── Phase-04-ATTCK-Fundamentals/
│   └── Phase-05-Attack-Simulations/
├── diagrams/
│   ├── network_architecture.png
│   └── detection_pipeline.png
├── screenshots/
├── detection-rules/
│   └── local_rules.xml
├── reports/
│   └── Enterprise-MITRE-ATTCK-Mapping-Lab-Report.docx
├── scripts/
└── README.md
```

## Custom detection rule

`detection-rules/local_rules.xml` includes rule `100213`, which corrects a real false positive in Wazuh's default rule `92213` without disabling it:

```xml
<rule id="100213" level="3">
  <if_sid>92213</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">
    (?i)__PSScriptPolicyTest_.+\.ps1$</field>
  <description>PowerShell internal script policy check artifact
    (expected behavior, not malware)</description>
  <options>no_full_log</options>
</rule>
```

## Full report

The complete engineering report, covering every phase, every screenshot, the full false-positive investigation and the confirmed detection gap, is available in [`reports/`](./reports).

## Roadmap

- [ ] Custom rule for the confirmed `schtasks.exe` / T1053.005 detection gap
- [ ] Phase 7: Hardening (PowerShell logging policy, AppLocker/WDAC, Defender, least privilege)
- [ ] Phase 9: Sigma rules, YARA, Microsoft Sentinel integration, purple team exercise

## Author

**IBNOUSOUFYANE Ayman**
IT Support Engineer, building toward Cybersecurity / Cloud / DevOps Engineering.
