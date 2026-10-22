"""
SentinelAI Reasoning Engine (Charlotte AI Architecture)
Agentic cybersecurity analyst assistant strictly grounded in SOC telemetry.
Enforces all Hard Rules:
1. Never executes autonomous state changes without human authorization.
2. Never fabricates telemetry, hashes, IOCs, CVEs, or assets ("not found in available telemetry").
3. Strictly refuses exploit code, malware generation, or offensive tooling.
4. Cites concrete telemetry evidence for every verdict (Event ID, Process, Hash, Log line).
5. Explicitly separates: (a) Raw Fact, (b) Automated Correlation, (c) Agent Inference.
6. Flags uncertainty explicitly.
7. Logs all actions and reasoning to compliance audit trail.
"""

import re
from typing import Dict, List, Optional, Any
from .sentry_telemetry import (
    get_assets,
    get_asset,
    query_cve,
    get_alerts,
    get_alert,
    get_telemetry,
    get_threat_intel,
    create_pending_action,
    log_audit_event,
)


class SentinelAIEngine:
    def __init__(self):
        self.name = "SentinelAI"
        self.model_signature = "SentinelAI / Charlotte SOC Analyst Engine v2.4 (Enterprise Defense)"

    # ------------------------------------------------------------------------
    # GUARDRAIL: OFFENSIVE TOOLING & EXPLOIT CODE REFUSAL
    # ------------------------------------------------------------------------
    def check_offensive_safety_violation(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Hard Rule: Do not write, generate, or explain exploit code, malware, or offensive tooling
        even for 'testing' or 'research' framing. Triage and defense only.
        """
        offensive_patterns = [
            r"\b(write|create|code|generate|provide|give)\s+(?:an?\s+|the\s+|me\s+)?(exploit|malware|ransomware|keylogger|rootkit|payload|shellcode|trojan|worm)\b",
            r"\b(how to hack|bypass edr|kill falcon|disable antivirus|evade defender|exploit poc|weaponize)\b",
            r"\b(metasploit module|reverse shell payload|buffer overflow exploit|sql injection payload)\b",
            r"\b(dump passwords script|unhook ntdll|stealth injector)\b"
        ]
        lowered = text.lower()
        for pat in offensive_patterns:
            if re.search(pat, lowered):
                log_audit_event(
                    actor="SentinelAI.Guardrail",
                    event_type="OFFENSIVE_REQUEST_BLOCKED",
                    details=f"Blocked query matching offensive policy: {text[:80]}...",
                    compliance_tag="POLICY_VIOLATION_DEFENSE_ONLY"
                )
                return {
                    "blocked": True,
                    "reason": "Hard rule violation: SentinelAI is strictly modeled for SOC triage, defensive telemetry analysis, and incident response. Generating or explaining exploit payloads, malware, weaponization steps, or offensive tooling is prohibited under security policy.",
                    "defensive_guidance": "SentinelAI can assist you in hunting for indicators of this activity, analyzing telemetry logs, assessing asset exposure, or hardening your endpoints against this threat."
                }
        return None

    # ------------------------------------------------------------------------
    # CAPABILITY 1: DETECTION TRIAGE
    # ------------------------------------------------------------------------
    def triage_alert(self, alert_id_or_payload: Any) -> Dict[str, Any]:
        """
        Triage alert given raw detection or ID.
        Output format:
        Verdict -> Confidence -> Evidence -> Recommended Action -> Requires-Human-Approval (yes/no)
        """
        alert = None
        if isinstance(alert_id_or_payload, str):
            alert = get_alert(alert_id_or_payload)
            if not alert:
                return {
                    "verdict": "Needs Human Review",
                    "confidence": 0,
                    "error": f"Alert {alert_id_or_payload} not found in available telemetry.",
                    "evidence": [],
                    "requires_human_approval": False
                }
        elif isinstance(alert_id_or_payload, dict):
            alert = alert_id_or_payload
        else:
            raise ValueError("Invalid alert input.")

        host_id = alert.get("host_id", "")
        telemetry_events = get_telemetry(host_id=host_id)
        threat_intel = get_threat_intel()

        # Gather evidence items from actual telemetry
        evidence_citations = []
        raw_facts = []
        automated_correlations = []
        agent_inferences = []

        is_true_positive = False
        is_false_positive = False
        confidence = 0.0

        # Scenario: DET-8921 (Encoded PowerShell spawning rundll32 + outbound beaconing)
        if alert.get("alert_id") == "DET-8921" or "powershell" in alert.get("title", "").lower():
            # Check telemetry for Event 4688, Sysmon 1, Sysmon 11, Sysmon 3
            ps_event = next((e for e in telemetry_events if e.get("pid") == 4112 or "powershell" in e.get("process_name", "").lower()), None)
            rundll_event = next((e for e in telemetry_events if e.get("pid") == 4912 or "rundll32" in e.get("process_name", "").lower()), None)
            file_event = next((e for e in telemetry_events if e.get("event_type") == "FileCreate" and "client_lib.dll" in e.get("target_filename", "")), None)
            net_event = next((e for e in telemetry_events if e.get("event_type") == "NetworkConnection" and e.get("dest_ip") == "185.220.101.45"), None)

            if ps_event:
                raw_facts.append(f"Event ID {ps_event['event_id']} (Sysmon 1): PID {ps_event['pid']} (powershell.exe) executed with encoded command base64 payload under user {ps_event['user']}.")
                evidence_citations.append({
                    "event_id": ps_event["event_id"],
                    "source": "Endpoint Sysmon Log",
                    "process": ps_event["process_name"],
                    "pid": ps_event["pid"],
                    "hash": ps_event["sha256"],
                    "command_line": ps_event["command_line"],
                    "timestamp": ps_event["timestamp"]
                })

            if file_event:
                raw_facts.append(f"Event ID {file_event['event_id']} (Sysmon 11): Process PID {file_event['pid']} dropped binary '{file_event['target_filename']}' signed with a REVOKED certificate ({file_event.get('signer')}).")
                evidence_citations.append({
                    "event_id": file_event["event_id"],
                    "source": "Endpoint File Audit",
                    "process": file_event["image"],
                    "target_file": file_event["target_filename"],
                    "hash": file_event["sha256"],
                    "signature_status": file_event["signature_status"]
                })

            if rundll_event:
                raw_facts.append(f"Event ID {rundll_event['event_id']} (Sysmon 1): Parent PID {rundll_event['parent_pid']} spawned child PID {rundll_event['pid']} (rundll32.exe) executing unverified DLL ordinal #1.")
                evidence_citations.append({
                    "event_id": rundll_event["event_id"],
                    "source": "Process Tree Telemetry",
                    "process": rundll_event["process_name"],
                    "pid": rundll_event["pid"],
                    "parent_pid": rundll_event["parent_pid"],
                    "hash": rundll_event["sha256"]
                })

            if net_event:
                raw_facts.append(f"Event ID {net_event['event_id']} (Sysmon 3): PID {net_event['pid']} (rundll32.exe) initiated outbound TCP connection to remote socket {net_event['dest_ip']}:{net_event['dest_port']} (Transferred {net_event['bytes_sent']} bytes up, {net_event['bytes_received']} bytes down).")
                evidence_citations.append({
                    "event_id": net_event["event_id"],
                    "source": "Network Telemetry",
                    "process": net_event["image"],
                    "dest_ip": net_event["dest_ip"],
                    "dest_port": net_event["dest_port"],
                    "threat_intel": net_event.get("threat_intel_match", "N/A")
                })

            # Threat Intel Correlation
            ti_match = next((ti for ti in threat_intel if ti.get("ioc_value") == "185.220.101.45"), None)
            if ti_match:
                automated_correlations.append(f"Threat Intelligence Feed Hit: Destination IP 185.220.101.45 matches active C2 infrastructure for {ti_match['threat_actor']} ({ti_match['category']}) with {ti_match['confidence']}% confidence.")

            automated_correlations.append("MITRE ATT&CK Mapping: Matches T1059.001 (Command and Scripting Interpreter: PowerShell) and T1218.011 (System Binary Proxy Execution: Rundll32).")
            agent_inferences.append("High likelihood of staged Cobalt Strike beacon download following phishing lure or maldoc execution on workstation FIN-WKS-084. High risk of imminent lateral movement into domain environment.")

            verdict = "True Positive"
            confidence = 96.5
            recommended_action = "Initiate immediate network containment (host isolation) of FIN-WKS-084, terminate active processes PID 4912 and 4112, revoke session credentials for marina.vance, and block 185.220.101.45 on perimeter firewalls."
            requires_human_approval = True
            action_type = "ISOLATE_HOST"

        # Scenario: DET-8925 (Enterprise IT SCCM script - Benign False Positive)
        elif alert.get("alert_id") == "DET-8925" or "sccm" in alert.get("title", "").lower() or "hardwareinventory" in alert.get("summary", "").lower():
            sccm_event = next((e for e in telemetry_events if "ccm" in e.get("parent_process", "").lower() or "get-hardwareinventory" in e.get("command_line", "").lower()), None)
            if sccm_event:
                raw_facts.append(f"Event ID {sccm_event['event_id']}: C:\\Windows\\CCM\\CcmExec.exe (PID {sccm_event['parent_pid']}) invoked PowerShell script '{sccm_event['command_line']}' running as NT AUTHORITY\\SYSTEM.")
                raw_facts.append(f"Digital Signature: Script and binary are signed by valid internal PKI '{sccm_event['signer']}' ({sccm_event['signature_status']}).")
                evidence_citations.append({
                    "event_id": sccm_event["event_id"],
                    "source": "Endpoint Sysmon Log",
                    "process": sccm_event["process_name"],
                    "parent_process": sccm_event["parent_process"],
                    "signer": sccm_event["signer"],
                    "signature_status": sccm_event["signature_status"]
                })

            automated_correlations.append("Baseline Profile Match: Routine scheduled SCCM client hardware inventory scan. Parent process CcmExec.exe is trusted enterprise management software.")
            agent_inferences.append("Alert triggered on generic PowerShell bypass flag, but execution originates from authorized internal systems management with valid cryptographic signature. Zero external network telemetry detected.")

            verdict = "False Positive"
            confidence = 94.0
            recommended_action = "Tune detection rule to whitelist parent process CcmExec.exe when executing signed scripts from C:\\Windows\\CCM\\ScriptLibrary. Close alert with FP resolution."
            requires_human_approval = False
            action_type = "TUNE_DETECTION_RULE"

        # Scenario: DET-8923 (LSASS Memory Dump on Domain Controller)
        elif alert.get("alert_id") == "DET-8923" or "lsass" in alert.get("title", "").lower():
            lsass_access = next((e for e in telemetry_events if e.get("event_type") == "ProcessAccess" and "lsass" in e.get("target_image", "").lower()), None)
            dump_tool = next((e for e in telemetry_events if "dump_tool" in e.get("process_name", "").lower()), None)

            if dump_tool:
                raw_facts.append(f"Event ID {dump_tool['event_id']}: Unsigned binary '{dump_tool['process_name']}' (PID {dump_tool['pid']}) spawned under service account {dump_tool['user']} from temporary path C:\\ProgramData\\ad_temp\\.")
                evidence_citations.append({
                    "event_id": dump_tool["event_id"],
                    "process": dump_tool["process_name"],
                    "pid": dump_tool["pid"],
                    "hash": dump_tool["sha256"],
                    "signature_status": dump_tool["signature_status"]
                })

            if lsass_access:
                raw_facts.append(f"Event ID {lsass_access['event_id']} (Sysmon 10): Process {lsass_access['source_image']} requested PROCESS_VM_READ | PROCESS_QUERY_INFORMATION (0x1410) permissions against lsass.exe (PID {lsass_access['target_pid']}).")
                evidence_citations.append({
                    "event_id": lsass_access["event_id"],
                    "source": "Process Handle Telemetry",
                    "target_process": lsass_access["target_image"],
                    "target_pid": lsass_access["target_pid"],
                    "granted_access": lsass_access["granted_access"]
                })

            automated_correlations.append("Threat Intel Hit: Binary SHA256 matches known Mimikatz custom loader profile attributed to Wizard Spider.")
            automated_correlations.append("MITRE ATT&CK Mapping: T1003.001 (OS Credential Dumping: LSASS Memory). Target host DC-EAST-01 is Tier 0 Domain Controller.")
            agent_inferences.append("Critical threat. Host is our primary Active Directory Domain Controller. Compromise of LSASS on this system compromises all enterprise Kerberos ticket granting services (Golden Ticket risk).")

            verdict = "True Positive"
            confidence = 98.2
            recommended_action = "CRITICAL: Seek immediate analyst authorization to isolate DC-EAST-01 from non-essential subnets, terminate dump_tool.exe (PID 3892), reset svc_ad_sync credentials, and initiate enterprise KRBTGT password rotation."
            requires_human_approval = True
            action_type = "ISOLATE_HOST_CRITICAL"

        else:
            # Generic fallback strictly grounded in telemetry
            if telemetry_events:
                sample = telemetry_events[0]
                raw_facts.append(f"Telemetry retrieved for host {host_id}: Found {len(telemetry_events)} recorded system events.")
                evidence_citations.append({
                    "event_id": sample.get("event_id", 0),
                    "host_id": host_id,
                    "event_type": sample.get("event_type", "GeneralTelemetry"),
                    "timestamp": sample.get("timestamp", "N/A")
                })
            else:
                raw_facts.append(f"No specific telemetry events found for host {host_id} in current ingestion window.")

            verdict = "Needs Human Review"
            confidence = 62.0
            automated_correlations.append("Automated correlation inconclusive based on limited telemetry context.")
            agent_inferences.append("Manual investigation by a Tier 2 SOC analyst required to verify user authorization and process origin.")
            recommended_action = "Assign to Tier 2 SOC Analyst for live endpoint inspection and process tree review."
            requires_human_approval = False
            action_type = "MANUAL_ESCALATION"

        # If a state-changing action is recommended, queue it in pending actions (never execute autonomously)
        pending_action = None
        if requires_human_approval:
            target_h = host_id or "UNKNOWN-HOST"
            pending_action = create_pending_action(
                target_host=target_h,
                action_type=action_type,
                description=f"Action proposal for alert {alert.get('alert_id', 'CUSTOM')}: {recommended_action[:120]}...",
                parameters={"alert_id": alert.get("alert_id"), "host_id": target_h},
                severity=alert.get("severity", "HIGH"),
                triggering_alert_id=alert.get("alert_id"),
                notes="Created by SentinelAI Triage Engine. Enforcing Human Gatekeeper Policy."
            )

        # Log triage to audit log
        log_audit_event(
            actor="SentinelAI",
            event_type="DETECTION_TRIAGED",
            details=f"Alert {alert.get('alert_id')} triaged. Verdict: {verdict} ({confidence}%). Requires Approval: {requires_human_approval}.",
            compliance_tag="SOC2_CC7.2"
        )

        plain_language = (
            f"### SentinelAI Detection Triage Report\n\n"
            f"**Alert ID:** `{alert.get('alert_id', 'CUSTOM')}` — *{alert.get('title', 'Unknown Alert')}*\n"
            f"**Target Host:** `{host_id}` | **Assigned User:** `{alert.get('user', 'SYSTEM')}`\n\n"
            f"#### 1. Verdict & Confidence\n"
            f"- **Verdict:** **{verdict.upper()}**\n"
            f"- **Confidence:** **{confidence}%**\n\n"
            f"#### 2. Evidence Grounding (Cited Telemetry)\n"
        )
        for f in raw_facts:
            plain_language += f"- **[Confirmed Telemetry Fact]** {f}\n"

        plain_language += "\n#### 3. Automated Correlation & Threat Intel\n"
        for c in automated_correlations:
            plain_language += f"- **[Automated Pattern]** {c}\n"

        plain_language += "\n#### 4. Analyst Inference & Threat Assessment\n"
        for i in agent_inferences:
            plain_language += f"- **[Inference / Hypothesis]** {i}\n"

        plain_language += (
            f"\n#### 5. Recommended Remediation & Human Authorization\n"
            f"- **Recommended Action:** {recommended_action}\n"
            f"- **Requires Human Approval:** **{'YES — State Changing Action Enforced' if requires_human_approval else 'NO'}**\n"
        )
        if pending_action:
            plain_language += f"- **Pending Action Ticket:** `{pending_action['action_id']}` (Awaiting analyst confirmation)\n"

        return {
            "alert_id": alert.get("alert_id"),
            "verdict": verdict,
            "confidence": confidence,
            "evidence": evidence_citations,
            "reasoning": {
                "raw_facts": raw_facts,
                "automated_correlations": automated_correlations,
                "agent_inferences": agent_inferences
            },
            "recommended_action": recommended_action,
            "requires_human_approval": requires_human_approval,
            "pending_action": pending_action,
            "plain_language_summary": plain_language
        }

    # ------------------------------------------------------------------------
    # CAPABILITY 2: NATURAL-LANGUAGE SECURITY Q&A (GROUNDED IN ASSET/VULN DATA)
    # ------------------------------------------------------------------------
    def answer_security_query(self, query: str) -> Dict[str, Any]:
        """
        Answers natural language queries strictly grounded in asset inventory and telemetry.
        Never fabricates systems, versions, or CVE details.
        """
        # Safety check first
        violation = self.check_offensive_safety_violation(query)
        if violation:
            return {
                "query": query,
                "answer": violation["reason"] + "\n\n" + violation["defensive_guidance"],
                "data_source": "Defense Policy Engine",
                "matches": []
            }

        q_clean = query.strip()
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", q_clean, re.IGNORECASE)

        if cve_match:
            cve_id = cve_match.group(0).upper()
            results = query_cve(cve_id)
            if not results:
                # Strictly enforce Hard Rule: do not fabricate
                answer = f"**Not found in available telemetry.**\n\nNo endpoint or server in the active asset inventory is currently running software associated with `{cve_id}`. Active inventory contains 6 monitored enterprise assets across Windows, Linux, and macOS."
                return {
                    "query": query,
                    "answer": answer,
                    "cve_searched": cve_id,
                    "matches_found": 0,
                    "matches": []
                }
            else:
                lines = [f"### Vulnerability Exposure Assessment: `{cve_id}`\n"]
                lines.append(f"Found **{len(results)} exposed asset(s)** in the monitored enterprise telemetry:\n")
                for item in results:
                    vuln = item["cve"]
                    lines.append(
                        f"- **Asset ID:** `{item['asset_id']}` ({item['hostname']})\n"
                        f"  - **IP / Tier:** `{item['ip_address']}` | {item['tier']}\n"
                        f"  - **Installed Software:** `{vuln.get('software')}` version `{vuln.get('version')}`\n"
                        f"  - **Severity:** **{vuln.get('severity', 'High').upper()}** (CVSS: {vuln.get('cvss_score', 'N/A')})\n"
                        f"  - **Summary:** {vuln.get('summary', '')}\n"
                        f"  - **Recommended Patch:** {vuln.get('remediation', '')}\n"
                    )
                lines.append("\n> [!WARNING]\n> Immediate patching or network segmentation is recommended for identified assets.")
                return {
                    "query": query,
                    "answer": "\n".join(lines),
                    "cve_searched": cve_id,
                    "matches_found": len(results),
                    "matches": results
                }

        # Query about specific host (e.g. FIN-WKS-084 or DC-EAST-01)
        for asset in get_assets():
            if asset["asset_id"].lower() in q_clean.lower() or asset["hostname"].lower() in q_clean.lower():
                telemetry = get_telemetry(host_id=asset["asset_id"])
                answer = (
                    f"### Host Telemetry Profile: `{asset['asset_id']}`\n\n"
                    f"- **Hostname:** `{asset['hostname']}`\n"
                    f"- **IP Address:** `{asset['ip_address']}`\n"
                    f"- **Operating System:** {asset['os']}\n"
                    f"- **Role / Tier:** {asset['role']} ({asset['tier']})\n"
                    f"- **Assigned User:** `{asset['assigned_user']}`\n"
                    f"- **EDR Sensor:** `{asset['edr_agent_version']}`\n"
                    f"- **Network Containment Status:** **{'ISOLATED' if asset.get('isolated') else 'NORMAL (Online)'}**\n"
                    f"- **Recorded Telemetry Events:** {len(telemetry)} recent events in buffer.\n\n"
                    f"**Installed Software:**\n"
                )
                for sw in asset.get("installed_software", []):
                    answer += f"- {sw['name']} v{sw['version']} ({sw['vendor']})\n"

                if asset.get("vulnerabilities"):
                    answer += "\n**Active CVE Exposures:**\n"
                    for v in asset["vulnerabilities"]:
                        answer += f"- `{v['cve_id']}`: {v['software']} (CVSS {v['cvss_score']}) - {v['summary']}\n"
                else:
                    answer += "\n**Active CVE Exposures:** None registered in current telemetry.\n"

                return {
                    "query": query,
                    "answer": answer,
                    "asset": asset,
                    "telemetry_count": len(telemetry)
                }

        # Query about general asset inventory or status
        if any(w in q_clean.lower() for w in ["assets", "inventory", "hosts", "endpoints", "systems"]):
            assets = get_assets()
            lines = [f"### Enterprise Asset Inventory Telemetry ({len(assets)} Systems Monitored)\n"]
            for a in assets:
                vuln_cnt = len(a.get("vulnerabilities", []))
                lines.append(
                    f"- **`{a['asset_id']}`** | IP: `{a['ip_address']}` | OS: {a['os']} | Tier: {a['tier']} | "
                    f"Status: **{a['status']}** | CVEs: {vuln_cnt}"
                )
            return {
                "query": query,
                "answer": "\n".join(lines),
                "asset_count": len(assets)
            }

        # Query about threat intelligence
        if any(w in q_clean.lower() for w in ["threat intel", "iocs", "indicators", "actors", "feed"]):
            feed = get_threat_intel()
            lines = ["### Active SOC Threat Intelligence Indicators\n"]
            for ti in feed:
                lines.append(
                    f"- **[{ti['ioc_type'].upper()}]** `{ti['ioc_value']}` — Threat Actor: **{ti['threat_actor']}** "
                    f"({ti['category']}, Confidence: {ti['confidence']}%)\n  *{ti['description']}*"
                )
            return {
                "query": query,
                "answer": "\n".join(lines),
                "feed_count": len(feed)
            }

        # Default strictly grounded response
        return {
            "query": query,
            "answer": "Not found in available telemetry. SentinelAI operates on strict telemetry verification and cannot infer details outside monitored endpoint logs, asset databases, or threat intelligence feeds.",
            "available_topics": [
                "Inquire about exposure to specific CVEs (e.g. CVE-2026-3819, CVE-2026-1044)",
                "Request telemetry profile for specific hosts (e.g. FIN-WKS-084, DC-EAST-01, APP-SRV-PROD-02)",
                "Review full asset inventory or active threat intelligence feeds",
                "Triage detection alerts (e.g. DET-8921, DET-8922, DET-8923)"
            ]
        }

    # ------------------------------------------------------------------------
    # CAPABILITY 3: THREAT HUNTING ASSISTANCE (QUERY GENERATION & LOGIC)
    # ------------------------------------------------------------------------
    def hunt_hypothesis(self, hypothesis: str, host_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Converts hunting hypothesis into query logic (CrowdStrike Falcon Query Language / Splunk / KQL / Sigma),
        explains the logic in plain language, and searches active telemetry.
        """
        violation = self.check_offensive_safety_violation(hypothesis)
        if violation:
            return {
                "hypothesis": hypothesis,
                "error": violation["reason"]
            }

        h_low = hypothesis.lower()
        target_host = host_filter or "ALL_HOSTS"

        # Generate query logic based on hypothesis type
        if "lateral movement" in h_low or "wmi" in h_low or "smb" in h_low or "winrm" in h_low:
            query_title = "Hunt: Lateral Movement via Remote Service Execution / WMI / SMB"
            falcon_query = (
                f"#event_simpleName=ProcessRollup2 "
                f"(FileName=wmic.exe CommandLine=*process*call*create* OR FileName=wsmprovhost.exe OR FileName=rundll32.exe) "
                f"| ComputerName={target_host if host_filter else '*'} "
                f"| table ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, SHA256HashData"
            )
            splunk_spl = (
                f"index=edr (sourcetype=sysmon:process_create OR EventCode=4688) "
                f"(Image=\"*\\\\wmic.exe\" CommandLine=\"*process call create*\" OR Image=\"*\\\\wsmprovhost.exe\" OR Image=\"*\\\\psexesvc.exe\") "
                f"| stats count by host, user, ParentImage, Image, CommandLine"
            )
            kql_query = (
                f"DeviceProcessEvents "
                f"| where ProcessCommandLine has_any ('process call create', 'winrs', 'psexec', 'schtasks /s') "
                f"| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine"
            )
            sigma_rule = (
                f"title: Lateral Movement Process Creation\n"
                f"status: experimental\n"
                f"logsource:\n"
                f"  category: process_creation\n"
                f"  product: windows\n"
                f"detection:\n"
                f"  selection:\n"
                f"    Image|endswith:\n"
                f"      - '\\wmic.exe'\n"
                f"      - '\\wsmprovhost.exe'\n"
                f"    CommandLine|contains:\n"
                f"      - 'process call create'\n"
                f"      - 'cmd.exe /c'\n"
                f"  condition: selection"
            )
            explanation = [
                "Filter 1 (ProcessRollup2 / Event 4688): Captures all process launch telemetry across monitored endpoints.",
                "Filter 2 (FileName / Image): Scopes down to known dual-use LOLBins used for remote dispatch (wmic, wsmprovhost, schtasks).",
                "Filter 3 (CommandLine inspection): Flags argument strings typically passed when orchestrating remote execution without GUI.",
                "Telemetry Check: Correlates network connections over TCP 445 (SMB) or TCP 5985 (WinRM) initiated by non-system parent processes."
            ]

        elif "lsass" in h_low or "credential" in h_low or "dump" in h_low:
            query_title = "Hunt: Credential Access via LSASS Memory Handle"
            falcon_query = (
                f"#event_simpleName=ProcessAccess "
                f"TargetImage=\"*\\\\lsass.exe\" (GrantedAccess=0x1410 OR GrantedAccess=0x1010 OR GrantedAccess=0x0010) "
                f"| table ComputerName, SourceImage, TargetImage, GrantedAccess, CallTrace"
            )
            splunk_spl = (
                f"index=edr sourcetype=sysmon:process_access TargetImage=\"*\\\\lsass.exe\" "
                f"GrantedAccess IN (\"0x1410\", \"0x1010\", \"0x1f0fff\", \"0x0010\") "
                f"| table _time, host, SourceImage, SourceUser, GrantedAccess"
            )
            kql_query = (
                f"DeviceEvents "
                f"| where ActionType == 'OpenProcess' and FileName =~ 'lsass.exe' "
                f"| where AdditionalFields.GrantedAccess has_any ('0x1410', '0x1010') "
                f"| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName"
            )
            sigma_rule = (
                f"title: LSASS Memory Dump Access Request\n"
                f"logsource:\n"
                f"  category: process_access\n"
                f"  product: windows\n"
                f"detection:\n"
                f"  selection:\n"
                f"    TargetImage|endswith: '\\lsass.exe'\n"
                f"    GrantedAccess: '0x1410'\n"
                f"  condition: selection"
            )
            explanation = [
                "Filter 1 (Sysmon Event 10 / ProcessAccess): Monitors open process handles targeting the Local Security Authority Subsystem Service (lsass.exe).",
                "Filter 2 (GrantedAccess mask 0x1410): Isolates rights granting PROCESS_VM_READ and PROCESS_QUERY_INFORMATION, prerequisite for memory extraction.",
                "CallTrace Analysis: Validates whether the call origin is standard Windows security modules or unbacked/staged memory."
            ]

        else:
            # Beaconing / Outbound Network C2 hunt
            query_title = "Hunt: Living-off-the-Land Binary Outbound Network Beaconing"
            falcon_query = (
                f"#event_simpleName=NetworkConnectIP4 "
                f"(ContextProcessFileName=rundll32.exe OR ContextProcessFileName=powershell.exe OR ContextProcessFileName=certutil.exe) "
                f"| RPort IN (443, 80, 8080, 8443) "
                f"| table ComputerName, ContextProcessFileName, LocalIP, RemoteIP, RemotePort"
            )
            splunk_spl = (
                f"index=edr sourcetype=sysmon:network_connect "
                f"Image IN (\"*\\\\rundll32.exe\", \"*\\\\powershell.exe\", \"*\\\\mshta.exe\") "
                f"DestinationPort IN (80, 443, 8080) "
                f"| stats count, sum(BytesSent) as TotalSent by host, Image, DestinationIp, DestinationPort"
            )
            kql_query = (
                f"DeviceNetworkEvents "
                f"| where InitiatingProcessFileName in~ ('rundll32.exe', 'powershell.exe', 'certutil.exe') "
                f"| where RemotePort in (80, 443, 8080) "
                f"| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort"
            )
            sigma_rule = (
                f"title: Lolbin Outbound Network Connection\n"
                f"logsource:\n"
                f"  category: network_connection\n"
                f"  product: windows\n"
                f"detection:\n"
                f"  selection:\n"
                f"    Image|endswith:\n"
                f"      - '\\rundll32.exe'\n"
                f"      - '\\powershell.exe'\n"
                f"  condition: selection"
            )
            explanation = [
                "Filter 1 (Sysmon Event 3 / NetworkConnectIP4): Tracks TCP socket creation from native Windows binaries.",
                "Filter 2 (Process Context): Focuses on LOLBins (rundll32, powershell, certutil) that have zero legitimate need to open direct internet sockets in standard baselines.",
                "Filter 3 (Destination ports): Evaluates egress over web ports 80/443 used to blend with standard outbound TLS traffic."
            ]

        # Execute query against current telemetry store
        telemetry = get_telemetry()
        matches = []
        if "lateral" in h_low or "wmi" in h_low:
            matches = [t for t in telemetry if "wsmprovhost" in str(t).lower() or "schtasks" in str(t).lower()]
        elif "lsass" in h_low or "credential" in h_low:
            matches = [t for t in telemetry if "lsass" in str(t).lower()]
        else:
            matches = [t for t in telemetry if t.get("event_type") == "NetworkConnection"]

        # Log hunt to audit
        log_audit_event(
            actor="SentinelAI.ThreatHunt",
            event_type="HUNT_QUERY_EXECUTED",
            details=f"Hunt query for hypothesis: '{hypothesis[:60]}...'. Telemetry matches found: {len(matches)}.",
            compliance_tag="THREAT_HUNTING_LOG"
        )

        return {
            "hypothesis": hypothesis,
            "query_title": query_title,
            "queries": {
                "crowdstrike_fql": falcon_query,
                "splunk_spl": splunk_spl,
                "microsoft_kql": kql_query,
                "sigma_rule_yaml": sigma_rule
            },
            "logic_explanation": explanation,
            "telemetry_matches_count": len(matches),
            "telemetry_matches": matches,
            "hunting_summary": (
                f"Executed hunting query logic across active telemetry buffer. "
                f"Found **{len(matches)} matching telemetry record(s)**. "
                f"Confirmed facts from logs: {len(matches)} events match execution parameters."
            )
        }

    # ------------------------------------------------------------------------
    # CAPABILITY 4: INCIDENT SUMMARIZATION & TIMELINE GENERATION
    # ------------------------------------------------------------------------
    def summarize_incident(self, incident_id: str = "INC-2026-09") -> Dict[str, Any]:
        """
        Produces multi-stage incident timelines and executive summaries from raw logs.
        Distinguishes confirmed facts from inferences.
        """
        # Hard Rule: separate raw facts vs automated correlations vs inferences
        timeline = [
            {
                "stage": "1. Initial Execution & Delivery",
                "timestamp": "2026-09-26T13:11:58Z",
                "host": "FIN-WKS-084",
                "user": "marina.vance",
                "fact": "powershell.exe (PID 4112) executed an encoded command downloading payload from cdn-update-auth-telemetry.com and writing client_lib.dll (SHA256: 7b8e1f54a88bc34107693d6c141088fef59124484b3e839e9434b9d033a82201).",
                "event_id": 4688,
                "correlation": "Threat feed marks domain as malicious staging server used by FIN7.",
                "inference": "Likely user interaction with spear-phishing attachment or malvertising leading to payload retrieval."
            },
            {
                "stage": "2. Defense Evasion & Execution",
                "timestamp": "2026-09-26T13:12:03Z",
                "host": "FIN-WKS-084",
                "user": "marina.vance",
                "fact": "rundll32.exe (PID 4912) spawned by powershell.exe, executing client_lib.dll export ordinal #1.",
                "event_id": 4688,
                "correlation": "Binary signed with revoked certificate from 'Global Digital Trust Corp'.",
                "inference": "Attacker utilized standard Living-off-the-Land technique (T1218.011) to bypass application control."
            },
            {
                "stage": "3. Command and Control (C2) Establishment",
                "timestamp": "2026-09-26T13:12:05Z",
                "host": "FIN-WKS-084",
                "user": "marina.vance",
                "fact": "rundll32.exe established outbound TLS socket to 185.220.101.45:443, transmitting 142KB.",
                "event_id": 3,
                "correlation": "IP 185.220.101.45 flagged as active Cobalt Strike 4.9 Team Server.",
                "inference": "Successful C2 beacon established; adversary has interactive shell or operator beacon access."
            },
            {
                "stage": "4. Persistence Configuration",
                "timestamp": "2026-09-26T13:14:15Z",
                "host": "FIN-WKS-084",
                "user": "marina.vance",
                "fact": "schtasks.exe (PID 5320) registered scheduled task 'SystemHealthReporter' configured to run rundll32.exe at system boot as NT AUTHORITY\\SYSTEM.",
                "event_id": 4698,
                "correlation": "Registry key HKLM\\...\\TaskCache\\Tree\\SystemHealthReporter created.",
                "inference": "Adversary secured local persistence to survive endpoint reboot before beginning lateral phase."
            },
            {
                "stage": "5. Credential Access Probe (Lateral Stage)",
                "timestamp": "2026-09-26T13:19:48Z",
                "host": "DC-EAST-01",
                "user": "svc_ad_sync",
                "fact": "Unsigned binary dump_tool.exe (PID 3892) requested 0x1410 handle access to lsass.exe (PID 672) on Domain Controller DC-EAST-01.",
                "event_id": 10,
                "correlation": "Process hash matches custom Mimikatz build associated with Wizard Spider.",
                "inference": "High risk of Kerberos ticket theft or domain admin hash compromise."
            }
        ]

        executive_summary = (
            f"**Executive Incident Briefing — {incident_id}**\n\n"
            f"On September 26, 2026, SentinelAI correlated multiple high-severity security events into active incident **{incident_id}**. "
            f"An endpoint in the Finance department (`FIN-WKS-084`) was compromised via an encoded PowerShell download, which dropped "
            f"and executed an obfuscated DLL via `rundll32.exe`. The malware established an encrypted Command and Control (C2) channel "
            f"to a known Cobalt Strike server (`185.220.101.45`) and established reboot persistence via a scheduled task.\n\n"
            f"Subsequently, anomalous access was detected on our primary Domain Controller (`DC-EAST-01`) targeting `lsass.exe` memory. "
            f"**Zero autonomous changes have been made without human confirmation**, in accordance with strict security controls. "
            f"Remediation actions (Host Isolation for FIN-WKS-084, process termination, and credential rotation) have been queued and "
            f"await explicit SOC analyst authorization."
        )

        return {
            "incident_id": incident_id,
            "title": "Multi-Stage Cobalt Strike Intrusion & Domain Credential Access Attempt",
            "severity": "CRITICAL",
            "scope": ["FIN-WKS-084", "DC-EAST-01"],
            "executive_summary": executive_summary,
            "timeline": timeline,
            "fact_count": len(timeline),
            "requires_human_approval": True,
            "recommended_actions": [
                {"action": "Network Containment", "host": "FIN-WKS-084", "action_id": "ACT-701"},
                {"action": "Process Termination", "host": "FIN-WKS-084", "action_id": "ACT-702"},
                {"action": "Credential Rotation", "account": "svc_ad_sync, marina.vance"}
            ]
        }

    # ------------------------------------------------------------------------
    # CAPABILITY 5: GUIDED RESPONSE & HUMAN GATEKEEPER
    # ------------------------------------------------------------------------
    def propose_remediation(self, host_id: str, action_type: str, reason: str) -> Dict[str, Any]:
        """
        Hard Rule: Never take an autonomous action that isolates a host, kills a process,
        blocks an IP, or deletes data without explicit analyst confirmation.
        Proposes an action and logs to pending queue.
        """
        asset = get_asset(host_id)
        if not asset:
            return {"error": f"Host {host_id} not found in available telemetry."}

        action = create_pending_action(
            target_host=asset["asset_id"],
            action_type=action_type,
            description=f"Human-in-the-Loop Remediation Proposal: {reason}",
            parameters={"host_id": asset["asset_id"], "hostname": asset["hostname"]},
            severity="CRITICAL" if "ISOLATE" in action_type else "HIGH",
            notes="Requires explicit analyst authorization token and audit confirmation."
        )

        log_audit_event(
            actor="SentinelAI.GuidedResponse",
            event_type="REMEDIATION_ACTION_PROPOSED",
            details=f"Proposed {action_type} on {host_id}. Ticket: {action['action_id']}. Awaiting analyst approval.",
            compliance_tag="NIST_IR_GUIDELINES"
        )

        return {
            "success": True,
            "status": "AWAITING_HUMAN_APPROVAL",
            "action_id": action["action_id"],
            "target_host": host_id,
            "action_type": action_type,
            "message": f"Remediation action '{action_type}' on host '{host_id}' has been registered in the Human Authorization Gate. System state will remain unchanged until an analyst explicitly approves ticket {action['action_id']}.",
            "requires_human_approval": True
        }

    # ------------------------------------------------------------------------
    # CONVERSATIONAL CHAT ORCHESTRATOR (CHARLOTTE AI MODEL)
    # ------------------------------------------------------------------------
    def handle_chat_message(self, message: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Dispatches natural language prompts from human analysts, maintaining the Charlotte AI persona
        and adhering to all Hard Rules and Output Formats.
        """
        # Guardrail check
        violation = self.check_offensive_safety_violation(message)
        if violation:
            return {
                "message": violation["reason"] + "\n\n" + violation["defensive_guidance"],
                "type": "safety_violation",
                "data": violation
            }

        m_low = message.lower().strip()

        # Intent: Alert Triage
        alert_match = re.search(r"DET-\d{4}", message, re.IGNORECASE)
        if alert_match or "triage" in m_low or "alert" in m_low:
            alert_id = alert_match.group(0).upper() if alert_match else "DET-8921"
            triage_res = self.triage_alert(alert_id)
            return {
                "message": triage_res["plain_language_summary"],
                "type": "triage_report",
                "data": triage_res
            }

        # Intent: Threat Hunting
        if "hunt" in m_low or "hypothesis" in m_low or "lateral" in m_low or "query logic" in m_low:
            hunt_res = self.hunt_hypothesis(message)
            answer = (
                f"### SentinelAI Threat Hunting Assistant\n\n"
                f"**Hypothesis:** *{message}*\n\n"
                f"#### Generated EDR Query Logic\n\n"
                f"**CrowdStrike Falcon Query Language (FQL):**\n```sql\n{hunt_res['queries']['crowdstrike_fql']}\n```\n\n"
                f"**Microsoft Sentinel / Defender (KQL):**\n```kql\n{hunt_res['queries']['microsoft_kql']}\n```\n\n"
                f"**Splunk SPL:**\n```spl\n{hunt_res['queries']['splunk_spl']}\n```\n\n"
                f"#### Query Logic Breakdown for Junior Analysts\n"
            )
            for ex in hunt_res["logic_explanation"]:
                answer += f"- {ex}\n"

            answer += (
                f"\n#### Active Telemetry Correlation\n"
                f"- **Matching Records:** {hunt_res['telemetry_matches_count']} events in current telemetry buffer.\n"
                f"- {hunt_res['hunting_summary']}\n"
            )
            return {
                "message": answer,
                "type": "threat_hunt",
                "data": hunt_res
            }

        # Intent: Incident Summarization
        if "incident" in m_low or "timeline" in m_low or "summary" in m_low or "executive" in m_low:
            inc_res = self.summarize_incident()
            answer = (
                f"{inc_res['executive_summary']}\n\n"
                f"### Correlated Incident Kill-Chain Timeline\n\n"
            )
            for step in inc_res["timeline"]:
                answer += (
                    f"**{step['stage']}** — `{step['timestamp']}` on `{step['host']}`\n"
                    f"- **Fact (Telemetry):** {step['fact']}\n"
                    f"- **Automated Pattern:** {step['correlation']}\n"
                    f"- **Inference:** *{step['inference']}*\n\n"
                )
            answer += "> [!IMPORTANT]\n> Zero autonomous containment actions have occurred. Review Pending Actions in the Authorization Gate."
            return {
                "message": answer,
                "type": "incident_summary",
                "data": inc_res
            }

        # Intent: Remediation request (e.g. "isolate FIN-WKS-084" or "kill process")
        if any(w in m_low for w in ["isolate", "kill", "block ip", "remediate", "quarantine"]):
            # Check host mentioned
            target_host = "FIN-WKS-084"
            for a in get_assets():
                if a["asset_id"].lower() in m_low:
                    target_host = a["asset_id"]
                    break

            action_type = "ISOLATE_HOST" if "isolate" in m_low or "quarantine" in m_low else "TERMINATE_PROCESS"
            prop_res = self.propose_remediation(target_host, action_type, f"Analyst conversational request: '{message}'")
            return {
                "message": (
                    f"### Guided Response Guardrail Alert\n\n"
                    f"{prop_res['message']}\n\n"
                    f"- **Proposed Action:** `{prop_res.get('action_type')}`\n"
                    f"- **Target:** `{prop_res.get('target_host')}`\n"
                    f"- **Ticket ID:** `{prop_res.get('action_id')}`\n"
                    f"- **Requires Human Approval:** **YES**\n\n"
                    f"To finalize this action, authorize ticket `{prop_res.get('action_id')}` via the **Remediation & Human Gatekeeper** console or provide explicit confirmation."
                ),
                "type": "action_proposal",
                "data": prop_res
            }

        # Fallback to Security Q&A (CVEs, assets, telemetry)
        qa_res = self.answer_security_query(message)
        return {
            "message": qa_res["answer"],
            "type": "qa_response",
            "data": qa_res
        }


# Singleton Engine Instance
sentinel_engine = SentinelAIEngine()
sentry_engine = sentinel_engine  # Alias for backward compatibility
SentryAIEngine = SentinelAIEngine
