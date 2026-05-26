#!/usr/bin/env python3
"""
Demo script: sends a curated batch of threat intelligence to the pipeline.

Usage:
    python3 scripts/demo_batch.py [--url <ingest-url>] [--delay <seconds>]

Defaults to the deployed stack's ingest URL. Use --delay to add a pause
between sends so judges can watch tickets appear in real-time (default: 2s).
"""

import argparse
import json
import sys
import time
import urllib.request

DEFAULT_URL = "https://3a7p6tcd7b.execute-api.us-east-1.amazonaws.com/prod/threats"

# Curated demo threats — realistic, diverse, and designed to show off
# classification accuracy, specialist domain expertise, and the update flow.
DEMO_THREATS = [
    # --- Wave 1: Initial threats across all categories ---
    {
        "name": "Siemens SIPROTEC 5 Protection Relay Denial of Service",
        "cve": "CVE-2026-90001",
        "description": (
            "A denial-of-service vulnerability in Siemens SIPROTEC 5 protection relays "
            "allows remote attackers to crash the relay by sending malformed IEC 61850 GOOSE "
            "messages. This causes the relay to enter a fail-open state, disabling protective "
            "tripping for the associated feeder. Affects firmware versions prior to 9.64."
        ),
        "category_hint": "scada",
    },
    {
        "name": "Palo Alto PAN-OS Zero-Day Command Injection in GlobalProtect",
        "cve": "CVE-2026-90002",
        "description": (
            "An unauthenticated command injection vulnerability in Palo Alto Networks PAN-OS "
            "GlobalProtect gateway allows remote code execution on the firewall. Active "
            "exploitation observed by UNC3886 targeting critical infrastructure VPN gateways. "
            "Affects PAN-OS 10.2.x and 11.0.x. Palo Alto has released an emergency hotfix."
        ),
        "category_hint": "network_operations",
    },
    {
        "name": "SAP S/4HANA ICM HTTP Request Smuggling",
        "cve": "CVE-2026-90003",
        "description": (
            "HTTP request smuggling in SAP S/4HANA Internet Communication Manager (ICM) "
            "allows unauthenticated attackers to bypass authentication and access internal "
            "RFC destinations. This can lead to extraction of financial data, modification "
            "of transactions, and lateral movement to connected SAP systems. SAP Security "
            "Note 3567890 provides the fix for S/4HANA 2022 and 2023."
        ),
        "category_hint": "apps_engineering",
    },
    {
        "name": "VMware ESXi OpenSLP Heap Overflow (ESXiArgs variant)",
        "cve": "CVE-2026-90004",
        "description": (
            "A new heap overflow variant in VMware ESXi OpenSLP service allows unauthenticated "
            "RCE on ESXi hosts exposed to the management network. A ransomware campaign dubbed "
            "'ESXiArgs-2' is actively mass-encrypting ESXi datastores across APAC. Affects "
            "ESXi 7.0 and 8.0 without the April 2026 patch."
        ),
        "category_hint": "infrastructure",
    },
    {
        "name": "Cisco Catalyst 9300 IOS-XE Web UI Implant (BadCanary)",
        "cve": "CVE-2026-90005",
        "description": (
            "A sophisticated implant dubbed 'BadCanary' has been discovered on Cisco Catalyst "
            "9300 switches running IOS-XE 17.6.x with the Web UI enabled. The implant "
            "intercepts authentication credentials and exfiltrates switch configurations via "
            "DNS tunneling. Initial access vector believed to be the previously patched "
            "CVE-2023-20198 chain in environments that haven't applied updates."
        ),
        "category_hint": "network_operations",
    },
    {
        "name": "Schneider Electric EcoStruxure Power Monitoring Expert SQL Injection",
        "cve": "CVE-2026-90006",
        "description": (
            "SQL injection in Schneider Electric EcoStruxure Power Monitoring Expert allows "
            "authenticated users to extract and modify power quality data, protection settings, "
            "and alarm configurations. The vulnerability is in the custom report generation "
            "module. Could allow an attacker to suppress alarms masking physical equipment damage."
        ),
        "category_hint": "scada",
    },
    {
        "name": "Microsoft 365 Entra ID Cross-Tenant Token Replay",
        "cve": "CVE-2026-90007",
        "description": (
            "A vulnerability in Microsoft Entra ID allows cross-tenant replay of primary "
            "refresh tokens under specific conditional access configurations. Attackers with "
            "a stolen PRT from one tenant can mint access tokens for any other tenant where "
            "the user has guest access. Microsoft has deployed a service-side fix."
        ),
        "category_hint": "apps_engineering",
    },
    {
        "name": "GE Mark VIe Turbine Controller Unauthorized Speed Control",
        "cve": "CVE-2026-90008",
        "description": (
            "GE Mark VIe turbine controllers allow unauthorized write access to speed "
            "reference setpoints via the EGD (Ethernet Global Data) protocol. An attacker "
            "on the control network could manipulate turbine speed causing equipment damage "
            "or forced shutdown. No authentication is required for EGD writes."
        ),
        "category_hint": "scada",
    },

    # --- Wave 2: Updates to existing threats (will trigger supersedes) ---
    {
        "name": "Siemens SIPROTEC 5 DoS - CONFIRMED exploitation at Australian utility",
        "cve": "CVE-2026-90001",
        "description": (
            "UPDATE: The Australian Cyber Security Centre (ACSC) has confirmed exploitation "
            "of CVE-2026-90001 at an Australian electricity utility. The attack caused "
            "protection relay failures across three substations, triggering manual intervention. "
            "SOCI Act reporting obligations have been triggered. All utilities with SIPROTEC 5 "
            "relays must apply firmware 9.64 immediately or implement network-level IEC 61850 "
            "GOOSE filtering."
        ),
        "category_hint": "scada (update)",
    },
    {
        "name": "VMware ESXiArgs-2 Ransomware - Decryptor released, IOCs updated",
        "cve": "CVE-2026-90004",
        "description": (
            "UPDATE: CISA has released a decryption tool for ESXiArgs-2 encrypted VMs where "
            "the flat-VMDK files remain intact. Additionally, updated IOCs have been published: "
            "C2 domains include esxi-update[.]cloud and vmware-patch[.]net. The ransomware "
            "only encrypts the first 1MB of each VMDK if the datastore exceeds 500GB, making "
            "partial recovery possible. Organisations should still patch immediately."
        ),
        "category_hint": "infrastructure (update)",
    },
]


def make_stix_object(index: int, threat: dict) -> dict:
    hex_index = f"{index:04x}"
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--de000000-{hex_index}-{hex_index}-{hex_index}-{index:012x}",
        "created": "2026-05-27T00:00:00.000Z",
        "modified": "2026-05-27T00:00:00.000Z",
        "name": threat["name"],
        "description": threat["description"],
        "external_references": [
            {"source_name": "cve", "external_id": threat["cve"]}
        ],
    }


def send_threat(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=15)
    return json.loads(resp.read())


def main():
    parser = argparse.ArgumentParser(description="Send demo threats to the pipeline")
    parser.add_argument("--url", default=DEFAULT_URL, help="Ingest API URL")
    parser.add_argument("--delay", type=float, default=2.0,
                        help="Seconds between sends (default: 2)")
    args = parser.parse_args()

    print(f"{'='*60}")
    print(f"  THREAT INTELLIGENCE PIPELINE - LIVE DEMO")
    print(f"  Endpoint: {args.url}")
    print(f"  Threats to send: {len(DEMO_THREATS)}")
    print(f"  Delay between sends: {args.delay}s")
    print(f"{'='*60}\n")

    wave1 = DEMO_THREATS[:8]
    wave2 = DEMO_THREATS[8:]

    print("━━━ WAVE 1: New threat intelligence arriving ━━━\n")
    for i, threat in enumerate(wave1, 1):
        stix = make_stix_object(i, threat)
        result = send_threat(args.url, stix)
        status_icon = "✓" if result["status"] == "accepted" else "✗"
        print(f"  [{status_icon}] {i:2d}. {threat['name'][:65]}")
        print(f"       → {result['status']} | threat_id: {result.get('threat_id', 'N/A')}")
        if i < len(wave1):
            time.sleep(args.delay)

    print(f"\n{'─'*60}")
    print(f"  Wave 1 complete. {len(wave1)} threats ingested.")
    print(f"  Waiting 10s for agents to process before sending updates...")
    print(f"{'─'*60}\n")
    time.sleep(10)

    print("━━━ WAVE 2: Updated intelligence (supersedes existing) ━━━\n")
    for i, threat in enumerate(wave2, len(wave1) + 1):
        stix = make_stix_object(i, threat)
        result = send_threat(args.url, stix)
        status_icon = "✓" if result["status"] == "accepted" else "✗"
        print(f"  [{status_icon}] {i:2d}. {threat['name'][:65]}")
        print(f"       → {result['status']} | threat_id: {result.get('threat_id', 'N/A')}")
        if "supersedes" in str(result):
            print(f"       ↳ supersedes previous threat")
        if i < len(DEMO_THREATS):
            time.sleep(args.delay)

    print(f"\n{'═'*60}")
    print(f"  Demo batch complete!")
    print(f"  • {len(wave1)} new threats sent (will create tickets)")
    print(f"  • {len(wave2)} updates sent (will add comments to existing tickets)")
    print(f"")
    print(f"  Watch the front-end for tickets appearing in ~30-60s.")
    print(f"  Check the dashboard for stats once processing completes.")
    print(f"{'═'*60}")


if __name__ == "__main__":
    main()
