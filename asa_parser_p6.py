# ============================================================
# ASA Migration Parser - Phase 6: Combined Report Generator
# ============================================================
# PURPOSE:
#   Imports and runs all Phase parsers (P1-P5) against a single
#   log file, then generates two output reports:
#
#   1. TECHNICAL REPORT (asa_migration_technical.txt)
#      Full parsed output organized by section. Intended for
#      the engineer executing the FTD migration. Includes all
#      rule counts, algorithm names, object references, risk
#      flags, and FMC action items.
#
#   2. EXECUTIVE REPORT (asa_migration_executive.txt)
#      Business-language summary. Intended for CIO, IT Director,
#      or customer stakeholder. No CLI syntax. Risk levels
#      translated to business impact. Counts translated to
#      effort estimates. Recommendations framed as decisions.
#
# USAGE:
#   python asa_parser_p6.py <path_to_log_file>
#   Example: python asa_parser_p6.py asa_logs.txt
#
# OUTPUTS:
#   asa_migration_technical.txt  — full technical report
#   asa_migration_executive.txt  — executive summary report
#   Both files written to same directory as the log file.
#
# DEPENDENCIES:
#   Requires all phase parser files in the same directory:
#     asa_parser_p3.py  (interface, route, VPN)
#     asa_parser_p4.py  (ACL, crypto, PKI)
#     asa_parser_p5.py  (NAT, objects, groups)
#
# DESIGN NOTES:
#   Phase 6 imports the parse functions from each phase module
#   directly. It does not re-implement any parsing logic.
#   All output is written to files — nothing is printed to
#   terminal except a brief status summary on completion.
# ============================================================

import sys
import os
import re
import io
from datetime import datetime
from collections import defaultdict

# ════════════════════════════════════════════════════════════
# DEPENDENCY CHECK
# ════════════════════════════════════════════════════════════

def check_dependencies():
    """
    Verifies all phase parser modules are present in the
    same directory as this script before attempting imports.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    required = [
        'asa_parser_p3.py',
        'asa_parser_p4.py',
        'asa_parser_p5.py',
    ]
    missing = []
    for f in required:
        if not os.path.isfile(os.path.join(script_dir, f)):
            missing.append(f)

    if missing:
        print("[ERROR] Missing required parser modules:")
        for m in missing:
            print(f"  - {m}")
        print()
        print("All phase parser files must be in the same")
        print("directory as asa_parser_p6.py.")
        sys.exit(1)


# ════════════════════════════════════════════════════════════
# PHASE MODULE IMPORTS
# ════════════════════════════════════════════════════════════

def import_phase_modules():
    """
    Adds script directory to path and imports parse functions
    from each phase module. Returns imported modules.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    import asa_parser_p3 as p3
    import asa_parser_p4 as p4
    import asa_parser_p5 as p5

    return p3, p4, p5


# ════════════════════════════════════════════════════════════
# SECTION EXTRACTION (shared)
# ════════════════════════════════════════════════════════════

SECTION_PATTERN = re.compile(
    r'^!\s*===SECTION:\s*([A-Z0-9_\-]+)\s*===$',
    re.IGNORECASE
)


def extract_sections(filepath):
    """Reads log file and returns { section_name: [lines] }."""
    sections_data = {}
    current_section = None

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n').rstrip('\r')
            stripped = line.strip()
            match = SECTION_PATTERN.match(stripped)
            if match:
                current_section = match.group(1).upper().strip()
                sections_data[current_section] = []
            elif current_section is not None:
                sections_data[current_section].append(line)

    return sections_data


# ════════════════════════════════════════════════════════════
# RUN ALL PARSERS
# ════════════════════════════════════════════════════════════

def run_all_parsers(sections_data, p3, p4, p5):
    """
    Runs all phase parsers against the extracted sections.
    Returns a dict of all parsed results keyed by data name.
    """
    results = {}

    # ── Phase 3 parsers ───────────────────────────────────────
    intf_lines = sections_data.get("INTERFACE-IP-BRIEF", [])
    results['interfaces'] = p3.parse_interface_brief(intf_lines) \
        if intf_lines else []

    route_lines = sections_data.get("ROUTE", [])
    results['routes'] = p3.parse_route_table(route_lines) \
        if route_lines else []

    vpn_lines = sections_data.get("VPN-SESSIONDB-SUMMARY", [])
    if vpn_lines:
        sessions, session_types = p3.parse_vpn_summary(vpn_lines)
        results['vpn_sessions'] = sessions
        results['vpn_session_types'] = session_types
    else:
        results['vpn_sessions'] = []
        results['vpn_session_types'] = []

    # ── Phase 4 parsers ───────────────────────────────────────
    acl_lines = sections_data.get("ACCESS-LIST", [])
    if acl_lines:
        acl_meta, acl_rules, acl_partials, acl_unmatched = \
            p4.parse_access_list_show(acl_lines)
        results['acl_meta']      = acl_meta
        results['acl_rules']     = acl_rules
        results['acl_partials']  = acl_partials
        results['acl_unmatched'] = acl_unmatched
    else:
        results['acl_meta'] = results['acl_rules'] = {}
        results['acl_partials'] = results['acl_unmatched'] = []

    cfg_acl_lines = sections_data.get("RUNNING-CONFIG-ACCESS-LIST", [])
    if cfg_acl_lines:
        cfg_rules, cfg_partials, cfg_unmatched = \
            p4.parse_running_config_acl(cfg_acl_lines)
        results['cfg_acl_rules']    = cfg_rules
        results['cfg_acl_partials'] = cfg_partials
        results['cfg_acl_unmatched'] = cfg_unmatched
    else:
        results['cfg_acl_rules'] = {}
        results['cfg_acl_partials'] = results['cfg_acl_unmatched'] = []

    crypto_lines = sections_data.get("RUNNING-CONFIG-CRYPTO", [])
    if crypto_lines:
        crypto_results = p4.parse_crypto(crypto_lines)
        (
            results['ikev1_policies'],
            results['ikev2_policies'],
            results['ikev1_ts'],
            results['ikev2_proposals'],
            results['ipsec_profiles'],
            results['dynamic_maps'],
            results['crypto_maps'],
            results['ike_enables'],
            results['map_interfaces'],
            results['isakmp_globals'],
            results['ipsec_globals'],
            results['sa_settings'],
            results['pki_trustpoints'],
            results['pki_cert_chains'],
            results['pki_ra_trustpoint'],
            results['pki_trustpool'],
            results['ikev1_am_disable'],
            results['crypto_partials'],
            results['crypto_unmatched'],
        ) = crypto_results
    else:
        for key in [
            'ikev1_policies', 'ikev2_policies', 'ikev1_ts',
            'ikev2_proposals', 'ipsec_profiles', 'isakmp_globals',
            'ipsec_globals', 'sa_settings', 'pki_trustpoints',
            'pki_cert_chains', 'pki_trustpool', 'crypto_partials',
            'crypto_unmatched',
        ]:
            results[key] = []
        for key in [
            'dynamic_maps', 'crypto_maps', 'ike_enables',
            'map_interfaces',
        ]:
            results[key] = {}
        results['pki_ra_trustpoint'] = None
        results['ikev1_am_disable']  = False

    # ── Phase 5 parsers ───────────────────────────────────────
    nat_lines = sections_data.get("RUNNING-CONFIG-ALL", [])
    nat_source = "RUNNING-CONFIG-ALL"
    if not nat_lines:
        nat_lines  = sections_data.get("RUNNING-CONFIG", [])
        nat_source = "RUNNING-CONFIG"

    results['nat_source'] = nat_source

    if nat_lines:
        (
            results['twice_nat_rules'],
            results['object_nat_rules'],
            results['network_objects'],
            results['network_groups'],
            results['nat_partials'],
            results['unmatched_nat'],
        ) = p5.parse_nat(nat_lines)
    else:
        results['twice_nat_rules']  = []
        results['object_nat_rules'] = []
        results['network_objects']  = {}
        results['network_groups']   = {}
        results['nat_partials']     = []
        results['unmatched_nat']    = []

    return results


# ════════════════════════════════════════════════════════════
# CAPTURE PHASE PRINT OUTPUT
# ════════════════════════════════════════════════════════════

def capture_output(func, *args, **kwargs):
    """
    Runs a print function and captures its stdout output
    as a string instead of printing to terminal.
    """
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        func(*args, **kwargs)
        output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    return output


# ════════════════════════════════════════════════════════════
# TECHNICAL REPORT BUILDER
# ════════════════════════════════════════════════════════════

def build_technical_report(results, p3, p4, p5,
                           filepath, sections_data):
    """
    Builds the full technical migration report by calling
    each phase's print functions and capturing their output.

    Returns the complete report as a string.
    """
    lines = []
    now   = datetime.now().strftime("%Y-%m-%d %H:%M")
    hostname = _extract_hostname(sections_data)

    lines.append("=" * 78)
    lines.append("  CISCO ASA TO FTD MIGRATION ANALYSIS — TECHNICAL REPORT")
    lines.append("=" * 78)
    lines.append(f"  Device    : {hostname}")
    lines.append(f"  Log file  : {os.path.basename(filepath)}")
    lines.append(f"  Generated : {now}")
    lines.append(f"  Sections  : {len(sections_data)} parsed from log file")
    lines.append("=" * 78)
    lines.append("")

    # ── Section 1: Platform ───────────────────────────────────
    lines.append(_section_header("1", "PLATFORM & VERSION"))
    version_info = _extract_version_info(sections_data)
    for k, v in version_info.items():
        lines.append(f"  {k:<25} : {v}")
    lines.append("")

    # ── Section 2: Interface Inventory ───────────────────────
    lines.append(_section_header("2", "INTERFACE INVENTORY"))
    lines.append(capture_output(
        p3.print_interface_brief, results['interfaces']
    ))

    # ── Section 3: Routing Table ──────────────────────────────
    lines.append(_section_header("3", "ROUTING TABLE"))
    lines.append(capture_output(
        p3.print_route_table, results['routes']
    ))

    # ── Section 4: VPN Sessions ───────────────────────────────
    lines.append(_section_header("4", "VPN SESSION SUMMARY"))
    lines.append(capture_output(
        p3.print_vpn_summary,
        results['vpn_sessions'],
        results['vpn_session_types'],
    ))

    # ── Section 5: Access Control Lists ──────────────────────
    lines.append(_section_header("5", "ACCESS CONTROL LIST ANALYSIS"))
    lines.append(capture_output(
        p4.print_access_list_show,
        results['acl_meta'],
        results['acl_rules'],
        results['acl_partials'],
        results['acl_unmatched'],
    ))
    lines.append(capture_output(
        p4.print_running_config_acl,
        results['cfg_acl_rules'],
        results['cfg_acl_partials'],
        results['cfg_acl_unmatched'],
    ))

    # ── Section 6: Crypto & PKI ───────────────────────────────
    lines.append(_section_header("6", "CRYPTO & PKI ANALYSIS"))
    lines.append(capture_output(
        p4.print_crypto,
        results['ikev1_policies'],
        results['ikev2_policies'],
        results['ikev1_ts'],
        results['ikev2_proposals'],
        results['ipsec_profiles'],
        results['dynamic_maps'],
        results['crypto_maps'],
        results['ike_enables'],
        results['map_interfaces'],
        results['isakmp_globals'],
        results['ipsec_globals'],
        results['sa_settings'],
        results['pki_trustpoints'],
        results['pki_cert_chains'],
        results['pki_ra_trustpoint'],
        results['pki_trustpool'],
        results['ikev1_am_disable'],
        results['crypto_partials'],
        results['crypto_unmatched'],
    ))

    # ── Section 7: NAT ────────────────────────────────────────
    lines.append(_section_header("7", "NAT ANALYSIS"))
    lines.append(capture_output(
        p5.print_twice_nat, results['twice_nat_rules']
    ))
    lines.append(capture_output(
        p5.print_object_nat,
        results['object_nat_rules'],
        results['network_objects'],
    ))
    lines.append(capture_output(
        p5.print_network_objects,
        results['network_objects'],
        results['network_groups'],
    ))
    lines.append(capture_output(
        p5.print_nat_summary,
        results['twice_nat_rules'],
        results['object_nat_rules'],
        results['network_objects'],
        results['network_groups'],
        results['nat_partials'],
        results['unmatched_nat'],
    ))

    # ── Section 8: Technical Migration Checklist ─────────────
    lines.append(_section_header("8", "TECHNICAL MIGRATION CHECKLIST"))
    lines.extend(_build_technical_checklist(results))
    lines.append("")

    # ── Footer ────────────────────────────────────────────────
    lines.append("=" * 78)
    lines.append("  END OF TECHNICAL REPORT")
    lines.append(f"  Generated by ASA Migration Parser Phase 6")
    lines.append(f"  {now}")
    lines.append("=" * 78)

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════
# EXECUTIVE REPORT BUILDER
# ════════════════════════════════════════════════════════════

def build_executive_report(results, filepath, sections_data):
    """
    Builds the executive summary report in plain business
    language. No CLI syntax. Risk translated to impact.
    Counts translated to effort. Designed for CIO / IT Director
    / customer stakeholder.

    Returns the complete report as a string.
    """
    lines = []
    now      = datetime.now().strftime("%Y-%m-%d %H:%M")
    hostname = _extract_hostname(sections_data)
    version_info = _extract_version_info(sections_data)

    lines.append("=" * 78)
    lines.append("  CISCO ASA TO FIREPOWER THREAT DEFENSE (FTD)")
    lines.append("  MIGRATION READINESS ASSESSMENT — EXECUTIVE SUMMARY")
    lines.append("=" * 78)
    lines.append(f"  Device         : {hostname}")
    lines.append(f"  Current System : Cisco ASA"
                 f" {version_info.get('Version', 'Unknown')}")
    lines.append(f"  Target System  : Cisco Firepower Threat Defense (FTD)")
    lines.append(f"  Report Date    : {now}")
    lines.append("=" * 78)
    lines.append("")

    # ── Purpose ───────────────────────────────────────────────
    lines.append(_exec_section("PURPOSE OF THIS DOCUMENT"))
    lines.append(
        "  This document summarizes the findings of an automated analysis\n"
        "  of the current firewall configuration. It is intended to help\n"
        "  decision-makers understand the scope, risk, and effort involved\n"
        "  in migrating from the current Cisco ASA firewall platform to\n"
        "  Cisco Firepower Threat Defense (FTD) — Cisco's next-generation\n"
        "  firewall platform with advanced threat inspection capabilities.\n"
    )

    # ── Executive Summary ─────────────────────────────────────
    lines.append(_exec_section("EXECUTIVE SUMMARY"))
    risk_level, risk_summary = _assess_overall_risk(results)
    lines.append(f"  Overall Migration Risk : {risk_level}")
    lines.append("")
    lines.append(f"  {risk_summary}")
    lines.append("")

    # ── What We Found ─────────────────────────────────────────
    lines.append(_exec_section("WHAT WE FOUND"))
    lines.extend(_build_exec_findings(results, version_info))

    # ── Migration Risks ───────────────────────────────────────
    lines.append(_exec_section("MIGRATION RISKS AND BUSINESS IMPACT"))
    lines.extend(_build_exec_risks(results))

    # ── Effort Estimate ───────────────────────────────────────
    lines.append(_exec_section("MIGRATION EFFORT ESTIMATE"))
    lines.extend(_build_exec_effort(results))

    # ── Pre-Migration Requirements ────────────────────────────
    lines.append(_exec_section("PRE-MIGRATION REQUIREMENTS"))
    lines.extend(_build_exec_prereqs(results))

    # ── Recommendations ───────────────────────────────────────
    lines.append(_exec_section("RECOMMENDATIONS"))
    lines.extend(_build_exec_recommendations(results))

    # ── Footer ────────────────────────────────────────────────
    lines.append("")
    lines.append("=" * 78)
    lines.append("  DISCLAIMER")
    lines.append("=" * 78)
    lines.append(
        "  This report was generated by automated configuration analysis.\n"
        "  All findings should be reviewed by a qualified network security\n"
        "  engineer before migration activities begin. This document does\n"
        "  not constitute a complete migration plan. Additional assessment\n"
        "  may be required for complex or non-standard configurations.\n"
    )
    lines.append("=" * 78)
    lines.append("  END OF EXECUTIVE SUMMARY")
    lines.append(f"  Generated by ASA Migration Parser Phase 6")
    lines.append(f"  {now}")
    lines.append("=" * 78)

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════
# EXECUTIVE REPORT HELPERS
# ════════════════════════════════════════════════════════════

def _assess_overall_risk(results):
    """
    Derives overall migration risk level from parsed results.
    Returns (risk_level_str, summary_str).
    """
    high_flags = []
    medium_flags = []

    # Inactive NAT
    inactive_nat = [r for r in results['twice_nat_rules']
                    if r['inactive']]
    if inactive_nat:
        high_flags.append(
            f"{len(inactive_nat)} disabled NAT rule(s) that must be "
            "cleaned up before migration"
        )

    # Inactive ACL rules
    total_inactive_acl = sum(
        1 for rules in results['acl_rules'].values()
        for r in rules if r['inactive']
    )
    if total_inactive_acl:
        high_flags.append(
            f"{total_inactive_acl} disabled firewall rule(s) requiring "
            "cleanup"
        )

    # Weak crypto
    weak_ts = [
        ts for ts in results['ikev1_ts']
        if ts['ftd_enc'] == 'REMOVED' or ts['ftd_hash'] == 'REMOVED'
    ]
    if weak_ts:
        high_flags.append(
            f"{len(weak_ts)} VPN encryption configuration(s) using "
            "algorithms that are not supported on the new platform — "
            "these VPN tunnels will fail post-migration without remediation"
        )

    # Dynamic maps
    if results['dynamic_maps']:
        high_flags.append(
            f"Remote access VPN configuration requires complete manual "
            "rebuild on the new platform — automatic migration tools "
            "cannot handle this"
        )

    # PKI RA trustpoint
    if results['pki_ra_trustpoint']:
        high_flags.append(
            "Security certificates used for remote access VPN must be "
            "manually exported and re-imported before employee VPN "
            "will function post-migration"
        )

    # Twice NAT
    if results['twice_nat_rules']:
        high_flags.append(
            f"{len(results['twice_nat_rules'])} network address "
            "translation rules require manual recreation — automatic "
            "migration tools will not handle these"
        )

    # Deprecated crypto
    deprecated_ts = [
        ts for ts in results['ikev1_ts']
        if ts['ftd_enc'] == 'DEPRECATED' or ts['ftd_hash'] == 'DEPRECATED'
    ]
    if deprecated_ts:
        medium_flags.append(
            f"{len(deprecated_ts)} VPN configuration(s) using older "
            "encryption standards — these will work initially but should "
            "be upgraded"
        )

    # Zero-hit ACL rules
    total_zero_hit = sum(
        1 for rules in results['acl_rules'].values()
        for r in rules if r['hitcnt'] == 0 and not r['inactive']
    )
    if total_zero_hit > 50:
        medium_flags.append(
            f"{total_zero_hit} firewall rules with no recorded traffic — "
            "review and cleanup recommended before migration to reduce "
            "complexity"
        )

    if len(high_flags) >= 3:
        risk_level = "HIGH"
        summary = (
            "This migration involves significant complexity and multiple\n"
            "  items that require manual intervention before or during\n"
            "  cutover. Without proper preparation, critical services\n"
            "  including VPN access and network connectivity could be\n"
            "  disrupted. A structured pre-migration remediation phase\n"
            "  is strongly recommended before scheduling the cutover window."
        )
    elif len(high_flags) >= 1:
        risk_level = "MEDIUM-HIGH"
        summary = (
            "This migration has identifiable risks that require attention\n"
            "  before cutover. With proper planning and pre-migration\n"
            "  remediation, the migration can proceed successfully.\n"
            "  Key items require engineer action before the cutover window."
        )
    elif medium_flags:
        risk_level = "MEDIUM"
        summary = (
            "This migration is manageable with standard planning. Some\n"
            "  items require review and cleanup before cutover but no\n"
            "  critical blockers were identified."
        )
    else:
        risk_level = "LOW"
        summary = (
            "No critical migration blockers identified. This migration\n"
            "  can proceed with standard planning and a normal cutover\n"
            "  window."
        )

    return risk_level, summary


def _build_exec_findings(results, version_info):
    """Builds the 'what we found' section in plain language."""
    lines = []

    # Network
    intfs   = results['interfaces']
    up_intf = [i for i in intfs if i['status'].lower() == 'up']
    routes  = results['routes']
    static  = [r for r in routes if 'Static' in r['type']]

    lines.append("  NETWORK CONFIGURATION")
    lines.append(f"  The firewall has {len(intfs)} network interfaces,"
                 f" {len(up_intf)} of which are currently active.")
    lines.append(f"  The routing table contains {len(routes)} routes,"
                 f" including {len(static)} static route(s).")
    lines.append("")

    # Firewall rules
    total_rules = sum(len(r) for r in results['acl_rules'].values())
    total_acls  = len(results['acl_rules'])
    inactive_acl = sum(
        1 for rules in results['acl_rules'].values()
        for r in rules if r['inactive']
    )
    zero_hit = sum(
        1 for rules in results['acl_rules'].values()
        for r in rules if r['hitcnt'] == 0 and not r['inactive']
    )

    lines.append("  FIREWALL RULES (ACCESS CONTROL)")
    lines.append(
        f"  The firewall contains {total_rules} security rules across "
        f"{total_acls} rule set(s)."
    )
    if inactive_acl:
        lines.append(
            f"  {inactive_acl} of these rules are currently disabled and "
            "must be removed before migration."
        )
    if zero_hit:
        lines.append(
            f"  {zero_hit} rules have never matched any traffic, suggesting "
            "they may be outdated and candidates for cleanup."
        )
    lines.append("")

    # VPN
    vpn_sessions = results['vpn_sessions']
    total_active = sum(s['active'] for s in vpn_sessions)
    has_anyconnect = any(
        'anyconnect' in s['session_type'].lower()
        for s in vpn_sessions
    )
    has_s2s = any(
        'site-to-site' in s['session_type'].lower()
        for s in vpn_sessions
    )

    ts_count  = len(results['ikev1_ts'])
    map_count = sum(len(v) for v in results['crypto_maps'].values())
    dyn_count = len(results['dynamic_maps'])

    lines.append("  VPN CONNECTIVITY")
    lines.append(
        f"  At the time of analysis, {total_active} active VPN session(s) "
        "were present."
    )
    if has_anyconnect:
        lines.append(
            "  Remote access VPN (employee VPN / AnyConnect) is in use."
        )
    if has_s2s:
        lines.append(
            "  Site-to-site VPN tunnels are active connecting to external"
            " partners or remote offices."
        )
    lines.append(
        f"  The firewall has {ts_count} VPN encryption profile(s) and "
        f"{map_count} VPN tunnel configuration(s)."
    )
    lines.append("")

    # NAT
    twice_count  = len(results['twice_nat_rules'])
    object_count = len(results['object_nat_rules'])
    total_nat    = twice_count + object_count

    lines.append("  NETWORK ADDRESS TRANSLATION (NAT)")
    lines.append(
        f"  The firewall performs {total_nat} network address translation "
        "operations."
    )
    lines.append(
        f"  {object_count} are simple translations that can be migrated "
        "automatically."
    )
    lines.append(
        f"  {twice_count} are complex policy-based translations that "
        "require manual recreation on the new platform."
    )
    lines.append("")

    # PKI
    tp_count = len(results['pki_trustpoints'])
    if tp_count:
        lines.append("  SECURITY CERTIFICATES")
        lines.append(
            f"  The firewall manages {tp_count} security certificate(s) "
            "used for encrypted communications and VPN authentication."
        )
        if results['pki_ra_trustpoint']:
            lines.append(
                "  One certificate is specifically used to authenticate "
                "employee VPN connections and must be migrated carefully."
            )
        lines.append("")

    return lines


def _build_exec_risks(results):
    """Builds business-language risk items."""
    lines = []

    # Classify risks
    high_risks   = []
    medium_risks = []
    low_risks    = []

    # VPN encryption incompatibility
    removed_ts = [
        ts for ts in results['ikev1_ts']
        if ts['ftd_enc'] == 'REMOVED' or ts['ftd_hash'] == 'REMOVED'
    ]
    if removed_ts:
        affected_maps = []
        for map_name, seqs in results['crypto_maps'].items():
            for seq, entry in seqs.items():
                weak_refs = [
                    t for t in entry['ikev1_ts']
                    if t.lower() in {
                        ts['name'].lower() for ts in removed_ts
                    }
                ]
                if weak_refs:
                    affected_maps.append(map_name)
        high_risks.append({
            'title'  : 'VPN Tunnels Will Fail Post-Migration',
            'detail' : (
                f"  {len(removed_ts)} VPN encryption profile(s) use "
                "security algorithms\n"
                "  that are not supported on the new FTD platform. "
                "If these are not\n"
                "  updated before cutover, the affected VPN tunnels will "
                "fail to\n"
                "  establish, disrupting connectivity with remote sites\n"
                "  or partners until remediated."
            ),
            'action' : (
                "  Update VPN encryption settings and coordinate with all "
                "remote VPN\n"
                "  peers before scheduling the migration window."
            ),
        })

    # RA VPN manual rebuild
    if results['dynamic_maps']:
        high_risks.append({
            'title'  : 'Employee VPN Requires Full Rebuild',
            'detail' : (
                "  The remote access VPN (employee VPN / AnyConnect) "
                "configuration\n"
                "  cannot be automatically migrated by Cisco's migration "
                "tools. It\n"
                "  must be completely rebuilt manually on the new platform."
            ),
            'action' : (
                "  Allocate dedicated engineering time to rebuild the "
                "remote access\n"
                "  VPN configuration in Firepower Management Center (FMC)\n"
                "  before the cutover window. Test thoroughly before cutover."
            ),
        })

    # PKI certificates
    if results['pki_ra_trustpoint']:
        high_risks.append({
            'title'  : 'VPN Certificates Must Be Manually Migrated',
            'detail' : (
                "  Security certificates used for employee VPN "
                "authentication must\n"
                "  be manually exported from the current firewall and "
                "imported\n"
                "  into the new system. If this step is missed, employee\n"
                "  VPN will not function after migration."
            ),
            'action' : (
                "  Export all certificates before the migration window and "
                "import\n"
                "  them into FMC as part of the pre-migration preparation."
            ),
        })

    # Twice NAT
    if results['twice_nat_rules']:
        inactive_nat = [r for r in results['twice_nat_rules']
                        if r['inactive']]
        high_risks.append({
            'title'  : f"Complex NAT Rules Require Manual Recreation"
                       f" ({len(results['twice_nat_rules'])} rules)",
            'detail' : (
                f"  {len(results['twice_nat_rules'])} complex network "
                "address translation rules cannot be\n"
                "  automatically migrated. These rules control how traffic "
                "is\n"
                "  translated between network segments and must be manually\n"
                "  recreated on the new platform."
                + (
                    f"\n  Additionally, {len(inactive_nat)} of these rules "
                    "are currently disabled\n"
                    "  and must be removed before migration can proceed."
                    if inactive_nat else ""
                )
            ),
            'action' : (
                "  Allocate engineering time to manually recreate these "
                "rules in FMC.\n"
                "  Review disabled rules with the customer to determine\n"
                "  whether they should be removed or re-enabled."
            ),
        })

    # Inactive ACL rules
    total_inactive_acl = sum(
        1 for rules in results['acl_rules'].values()
        for r in rules if r['inactive']
    )
    if total_inactive_acl:
        high_risks.append({
            'title'  : f"Disabled Firewall Rules Must Be Removed"
                       f" ({total_inactive_acl} rules)",
            'detail' : (
                f"  {total_inactive_acl} firewall rules are currently "
                "disabled using a feature\n"
                "  that does not exist on the new FTD platform. These "
                "rules must\n"
                "  be permanently removed before migration. If not removed,\n"
                "  the migration process may fail or produce incorrect "
                "results."
            ),
            'action' : (
                "  Review disabled rules with the customer. Determine "
                "whether each\n"
                "  should be permanently deleted or converted to an active "
                "rule.\n"
                "  Remove all disabled rules before migration."
            ),
        })

    # Deprecated crypto
    deprecated_ts = [
        ts for ts in results['ikev1_ts']
        if ts['ftd_enc'] == 'DEPRECATED' or
           ts['ftd_hash'] == 'DEPRECATED'
    ]
    if deprecated_ts:
        medium_risks.append({
            'title'  : f"VPN Uses Older Encryption Standards"
                       f" ({len(deprecated_ts)} profile(s))",
            'detail' : (
                f"  {len(deprecated_ts)} VPN encryption profile(s) use "
                "security algorithms that\n"
                "  are considered outdated. While they will function "
                "initially\n"
                "  after migration, Cisco has flagged these for removal in\n"
                "  future FTD versions and they represent a security risk."
            ),
            'action' : (
                "  Plan an encryption upgrade for these VPN profiles "
                "within 6 months\n"
                "  of migration. Coordinate with remote VPN peers."
            ),
        })

    # Zero-hit rules
    total_zero_hit = sum(
        1 for rules in results['acl_rules'].values()
        for r in rules if r['hitcnt'] == 0 and not r['inactive']
    )
    if total_zero_hit > 20:
        medium_risks.append({
            'title'  : f"Potentially Outdated Firewall Rules"
                       f" ({total_zero_hit} rules)",
            'detail' : (
                f"  {total_zero_hit} firewall rules have never matched any "
                "network traffic.\n"
                "  These rules may be outdated, redundant, or misconfigured.\n"
                "  Migrating unnecessary rules increases complexity and\n"
                "  makes future policy management more difficult."
            ),
            'action' : (
                "  Review unused rules with the customer before migration.\n"
                "  Remove confirmed unnecessary rules to simplify the\n"
                "  migrated policy."
            ),
        })

    # Dynamic routing
    from collections import defaultdict
    grouped_routes = defaultdict(list)
    for r in results['routes']:
        grouped_routes[r['type']].append(r)
    dynamic_types = [
        t for t in grouped_routes
        if t not in ('Connected', 'Local', 'Static', 'Static Default')
    ]
    if dynamic_types:
        medium_risks.append({
            'title'  : "Dynamic Routing Requires Manual Reconfiguration",
            'detail' : (
                f"  Dynamic routing protocols ({', '.join(dynamic_types)}) "
                "are in use.\n"
                "  These routing configurations are not automatically "
                "migrated\n"
                "  and must be manually reconfigured on the new platform."
            ),
            'action' : (
                "  Document current dynamic routing configuration and "
                "rebuild\n"
                "  it in FMC as part of the migration preparation."
            ),
        })

    # Print risks
    if high_risks:
        lines.append("  HIGH IMPACT ITEMS — Require action before cutover:")
        lines.append("  " + "-" * 60)
        for i, risk in enumerate(high_risks, 1):
            lines.append(f"\n  {i}. {risk['title']}")
            lines.append(f"\n     What it means:")
            lines.append(risk['detail'])
            lines.append(f"\n     Required action:")
            lines.append(risk['action'])
        lines.append("")

    if medium_risks:
        lines.append(
            "  MEDIUM IMPACT ITEMS — Plan to address during/after migration:"
        )
        lines.append("  " + "-" * 60)
        for i, risk in enumerate(medium_risks, 1):
            lines.append(f"\n  {i}. {risk['title']}")
            lines.append(f"\n     What it means:")
            lines.append(risk['detail'])
            lines.append(f"\n     Required action:")
            lines.append(risk['action'])
        lines.append("")

    if not high_risks and not medium_risks:
        lines.append(
            "  No significant migration risks identified. Standard\n"
            "  migration planning applies."
        )
        lines.append("")

    return lines


def _build_exec_effort(results):
    """Builds plain-language effort estimate."""
    lines = []

    twice_count  = len(results['twice_nat_rules'])
    ts_removed   = sum(
        1 for ts in results['ikev1_ts']
        if ts['ftd_enc'] == 'REMOVED' or ts['ftd_hash'] == 'REMOVED'
    )
    has_ra_vpn   = bool(results['dynamic_maps'])
    has_pki      = bool(results['pki_trustpoints'])
    total_rules  = sum(len(r) for r in results['acl_rules'].values())

    # Rough effort tiers
    effort_items = []

    effort_items.append(
        f"  Firewall rule migration ({total_rules} rules)"
        f"             : 4-8 hours"
    )

    if twice_count:
        hrs = max(4, min(twice_count // 20, 40))
        effort_items.append(
            f"  Complex NAT rule recreation ({twice_count} rules)"
            f"         : {hrs}-{hrs*2} hours"
        )

    if has_ra_vpn:
        effort_items.append(
            f"  Remote access VPN rebuild"
            f"                          : 4-8 hours"
        )

    if ts_removed:
        effort_items.append(
            f"  VPN encryption remediation ({ts_removed} profile(s))"
            f"       : 2-4 hours"
        )

    if has_pki:
        effort_items.append(
            f"  Certificate export and import"
            f"                      : 1-2 hours"
        )

    effort_items.append(
        f"  Testing and validation"
        f"                             : 4-8 hours"
    )
    effort_items.append(
        f"  Cutover window and rollback preparation"
        f"            : 2-4 hours"
    )

    total_low  = sum(
        int(e.split(': ')[1].split('-')[0].split()[0])
        for e in effort_items
    )
    total_high = sum(
        int(e.split(': ')[1].split('-')[-1].split()[0])
        for e in effort_items
    )

    lines.append(
        "  The following effort estimates are based on the complexity\n"
        "  of the configuration found during analysis. These are\n"
        "  estimates only and may vary based on environment factors.\n"
    )
    lines.append("  EFFORT BREAKDOWN")
    lines.append("  " + "-" * 60)
    for item in effort_items:
        lines.append(item)
    lines.append("  " + "-" * 60)
    lines.append(
        f"  TOTAL ESTIMATED EFFORT"
        f"                             : "
        f"{total_low}-{total_high} hours"
    )
    lines.append("")
    lines.append(
        "  Note: These estimates assume an experienced Cisco security\n"
        "  engineer familiar with both ASA and FTD platforms. Estimates\n"
        "  do not include project management, change control, or\n"
        "  stakeholder communication time.\n"
    )

    return lines


def _build_exec_prereqs(results):
    """Builds pre-migration requirements list."""
    lines = []
    prereqs = []

    # Always required
    prereqs.append(
        "Obtain Cisco Firepower Management Center (FMC) access and "
        "verify FTD hardware is staged and reachable"
    )
    prereqs.append(
        "Schedule a maintenance window — active network connections "
        "and VPN sessions will be interrupted during cutover"
    )
    prereqs.append(
        "Notify all VPN users (remote employees and site-to-site "
        "partners) of the planned maintenance window"
    )
    prereqs.append(
        "Create a rollback plan — document how to restore the ASA "
        "configuration if the migration needs to be reversed"
    )

    # Conditional
    if results['pki_trustpoints']:
        prereqs.append(
            "Export all security certificates from the current ASA "
            "before the maintenance window begins"
        )

    total_inactive = sum(
        1 for rules in results['acl_rules'].values()
        for r in rules if r['inactive']
    ) + len([r for r in results['twice_nat_rules'] if r['inactive']])

    if total_inactive:
        prereqs.append(
            f"Remove all {total_inactive} disabled rule(s) from the "
            "firewall configuration before migration begins"
        )

    weak_ts = [
        ts for ts in results['ikev1_ts']
        if ts['ftd_enc'] == 'REMOVED' or ts['ftd_hash'] == 'REMOVED'
    ]
    if weak_ts:
        prereqs.append(
            "Update VPN encryption profiles to use supported algorithms "
            "and coordinate changes with all remote VPN peers"
        )

    if results['dynamic_maps']:
        prereqs.append(
            "Document the complete remote access VPN configuration "
            "and prepare the FMC rebuild plan before the window"
        )

    for i, prereq in enumerate(prereqs, 1):
        lines.append(f"  {i}. {prereq}")

    lines.append("")
    return lines


def _build_exec_recommendations(results):
    """Builds executive-level recommendations."""
    lines = []

    has_high_risk = (
        bool([ts for ts in results['ikev1_ts']
              if ts['ftd_enc'] == 'REMOVED']) or
        bool(results['dynamic_maps']) or
        bool([r for r in results['twice_nat_rules'] if r['inactive']]) or
        sum(1 for rules in results['acl_rules'].values()
            for r in rules if r['inactive']) > 0
    )

    if has_high_risk:
        lines.append(
            "  1. DO NOT schedule the migration cutover window until all\n"
            "     HIGH IMPACT items listed above have been remediated.\n"
            "     Proceeding without remediation risks service disruption.\n"
        )
    else:
        lines.append(
            "  1. This migration can proceed to planning and scheduling.\n"
            "     No critical blockers were identified that would prevent\n"
            "     a successful migration with standard preparation.\n"
        )

    lines.append(
        "  2. Engage a Cisco-certified security engineer to execute\n"
        "     the technical migration. Firepower Threat Defense has\n"
        "     a different management model than ASA and requires\n"
        "     platform-specific expertise.\n"
    )

    lines.append(
        "  3. Plan for a testing period of at least 48-72 hours\n"
        "     after cutover before considering the migration complete.\n"
        "     Keep the old ASA configuration accessible for rollback\n"
        "     during this period.\n"
    )

    zero_hit = sum(
        1 for rules in results['acl_rules'].values()
        for r in rules if r['hitcnt'] == 0 and not r['inactive']
    )
    if zero_hit > 20:
        lines.append(
            f"  4. Use this migration as an opportunity to clean up\n"
            f"     the firewall policy. {zero_hit} rules have never\n"
            f"     matched any traffic and may be candidates for removal.\n"
            f"     A cleaner policy is easier to manage and audit.\n"
        )

    deprecated_ts = [
        ts for ts in results['ikev1_ts']
        if ts['ftd_enc'] == 'DEPRECATED' or
           ts['ftd_hash'] == 'DEPRECATED'
    ]
    if deprecated_ts:
        lines.append(
            f"  5. Plan a follow-up project to upgrade {len(deprecated_ts)}\n"
            f"     VPN encryption configuration(s) to current security\n"
            f"     standards within 6 months of the migration. These\n"
            f"     configurations will function after migration but\n"
            f"     represent a security gap.\n"
        )

    return lines


# ════════════════════════════════════════════════════════════
# TECHNICAL CHECKLIST BUILDER
# ════════════════════════════════════════════════════════════

def _build_technical_checklist(results):
    """
    Builds an ordered technical migration checklist derived
    from all parsed findings.
    """
    lines = []
    checklist = []

    # Pre-migration
    total_inactive_acl = sum(
        1 for rules in results['acl_rules'].values()
        for r in rules if r['inactive']
    )
    inactive_nat = [r for r in results['twice_nat_rules'] if r['inactive']]

    checklist.append(("PRE-MIGRATION", [
        "Run Cisco Firepower Migration Tool (FMT) against ASA config — "
        "review output before applying to FTD",
        "Verify FMC version is compatible with target FTD platform version",
        "Confirm FTD HA pair is staged and failover is configured",
    ]))

    # Cleanup items
    cleanup = []
    if total_inactive_acl:
        cleanup.append(
            f"Remove {total_inactive_acl} inactive ACL rule(s) — "
            "FTD does not support the 'inactive' keyword"
        )
    if inactive_nat:
        cleanup.append(
            f"Remove {len(inactive_nat)} inactive Twice NAT rule(s)"
        )
    removed_ts = [
        ts for ts in results['ikev1_ts']
        if ts['ftd_enc'] == 'REMOVED' or ts['ftd_hash'] == 'REMOVED'
    ]
    if removed_ts:
        cleanup.append(
            f"Update {len(removed_ts)} IKEv1 transform set(s) — "
            "DES/3DES/MD5 not supported on FTD — coordinate with peers"
        )
    if cleanup:
        checklist.append(("PRE-MIGRATION CLEANUP", cleanup))

    # PKI
    if results['pki_trustpoints']:
        pki_items = [
            f"Export {len(results['pki_trustpoints'])} trustpoint(s): "
            "crypto ca export <n> pkcs12 <password>",
            "Import certificates into FMC: Objects > PKI > Cert Enrollment",
        ]
        if results['pki_ra_trustpoint']:
            pki_items.append(
                f"Assign trustpoint '{results['pki_ra_trustpoint']}' to "
                "AnyConnect Connection Profile in FMC"
            )
        checklist.append(("PKI / CERTIFICATES", pki_items))

    # VPN
    vpn_items = []
    if results['dynamic_maps']:
        vpn_items.append(
            f"Manually rebuild {len(results['dynamic_maps'])} dynamic map(s) "
            "as RA VPN Connection Profile(s) in FMC"
        )
    if results['crypto_maps']:
        map_total = sum(len(v) for v in results['crypto_maps'].values())
        vpn_items.append(
            f"Verify {map_total} S2S crypto map entr(ies) migrated correctly"
        )
    vpn_items.append(
        "Test all IKEv1 and IKEv2 tunnels post-migration"
    )
    vpn_items.append(
        "Test AnyConnect client connectivity from multiple endpoints"
    )
    if vpn_items:
        checklist.append(("VPN", vpn_items))

    # NAT
    nat_items = []
    if results['twice_nat_rules']:
        nat_items.append(
            f"Manually recreate {len(results['twice_nat_rules'])} Twice NAT "
            "rules in FMC: Devices > NAT > Add Rule > Manual NAT"
        )
    nat_items.append(
        "Verify Object NAT rules migrated correctly via FMT"
    )
    nat_items.append(
        "Test NAT translations with traffic captures post-migration"
    )
    checklist.append(("NAT", nat_items))

    # Post-migration validation
    checklist.append(("POST-MIGRATION VALIDATION", [
        "Verify all interfaces are up and passing traffic",
        "Confirm routing table matches pre-migration state",
        "Test all VPN tunnels — both S2S and RA VPN",
        "Verify NAT translations with packet captures",
        "Confirm logging is reaching syslog destination(s)",
        "Confirm AAA authentication is functioning",
        "Run 'show failover' to confirm HA state is Active/Standby",
        "Keep ASA config accessible for rollback for minimum 72 hours",
    ]))

    # Format and output
    item_num = 1
    for phase, items in checklist:
        lines.append(f"  [{phase}]")
        for item in items:
            lines.append(f"  {item_num:>3}. {item}")
            item_num += 1
        lines.append("")

    return lines


# ════════════════════════════════════════════════════════════
# UTILITY HELPERS
# ════════════════════════════════════════════════════════════

def _extract_hostname(sections_data):
    """Extracts hostname from version section if available."""
    version_lines = sections_data.get("VERSION", [])
    if not version_lines:
        version_lines = sections_data.get("RUNNING-CONFIG", [])[:50]
    for line in version_lines:
        m = re.match(r'^hostname\s+(\S+)', line.strip(), re.IGNORECASE)
        if m:
            return m.group(1)
    return "(hostname not found)"


def _extract_version_info(sections_data):
    """Extracts ASA version, model, and serial from version section."""
    info = {}
    version_lines = sections_data.get(
        "VERSION",
        sections_data.get("RUNNING-CONFIG-ALL", [])[:100]
    )

    for line in version_lines:
        s = line.strip()
        # Cisco Adaptive Security Appliance Software Version 9.16(4)11
        m = re.match(
            r'^Cisco Adaptive Security Appliance Software Version\s+(\S+)',
            s, re.IGNORECASE
        )
        if m:
            info['Version'] = m.group(1)

        # Hardware: ASA5545, 12288 MB RAM
        m = re.match(r'^Hardware:\s+(\S+)', s, re.IGNORECASE)
        if m:
            info['Model'] = m.group(1).rstrip(',')

        # Serial Number: ABC1234567
        m = re.match(r'^Serial Number:\s+(\S+)', s, re.IGNORECASE)
        if m:
            info['Serial'] = m.group(1)

        # hostname <name>
        m = re.match(r'^hostname\s+(\S+)', s, re.IGNORECASE)
        if m:
            info['Hostname'] = m.group(1)

    if not info:
        info['Note'] = 'Version section not available in log file'

    return info


def _section_header(num, title):
    """Returns a formatted technical report section header."""
    return (
        f"\n{'='*78}\n"
        f"  SECTION {num}: {title}\n"
        f"{'='*78}\n"
    )


def _exec_section(title):
    """Returns a formatted executive report section header."""
    return (
        f"\n{'─'*78}\n"
        f"  {title}\n"
        f"{'─'*78}\n"
    )


# ════════════════════════════════════════════════════════════
# WRITE REPORTS
# ════════════════════════════════════════════════════════════

def write_report(content, filepath):
    """Writes report content to a file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) != 2:
        print("Usage: python asa_parser_p6.py <path_to_log_file>")
        print("Example: python asa_parser_p6.py asa_logs.txt")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.isfile(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    if os.path.getsize(filepath) == 0:
        print(f"[ERROR] File is empty: {filepath}")
        sys.exit(1)

    print()
    print("=" * 60)
    print("  ASA MIGRATION PARSER — PHASE 6")
    print("  Generating Technical + Executive Reports")
    print("=" * 60)

    # ── Dependency check ──────────────────────────────────────
    print("\n  [1/5] Checking dependencies...")
    check_dependencies()
    print("        OK")

    # ── Import phase modules ──────────────────────────────────
    print("  [2/5] Loading parser modules...")
    p3, p4, p5 = import_phase_modules()
    print("        OK")

    # ── Extract sections ──────────────────────────────────────
    print("  [3/5] Extracting sections from log file...")
    sections_data = extract_sections(filepath)
    print(f"        {len(sections_data)} section(s) found")

    # ── Run all parsers ───────────────────────────────────────
    print("  [4/5] Running all parsers...")
    results = run_all_parsers(sections_data, p3, p4, p5)
    print(f"        Interfaces    : {len(results['interfaces'])}")
    print(f"        Routes        : {len(results['routes'])}")
    print(f"        VPN sessions  : {len(results['vpn_sessions'])}")
    total_rules = sum(len(r) for r in results['acl_rules'].values())
    print(f"        ACL rules     : {total_rules}")
    print(f"        Transform sets: {len(results['ikev1_ts'])}")
    print(f"        Crypto maps   : "
          f"{sum(len(v) for v in results['crypto_maps'].values())}")
    print(f"        Trustpoints   : {len(results['pki_trustpoints'])}")
    total_nat = (len(results['twice_nat_rules']) +
                 len(results['object_nat_rules']))
    print(f"        NAT rules     : {total_nat}")
    print(f"        Net objects   : {len(results['network_objects'])}")

    # ── Build and write reports ───────────────────────────────
    print("  [5/5] Generating reports...")

    log_dir = os.path.dirname(os.path.abspath(filepath))
    tech_path = os.path.join(log_dir, "asa_migration_technical.txt")
    exec_path = os.path.join(log_dir, "asa_migration_executive.txt")

    tech_report = build_technical_report(
        results, p3, p4, p5, filepath, sections_data
    )
    write_report(tech_report, tech_path)
    print(f"        Technical report : {tech_path}")

    exec_report = build_executive_report(
        results, filepath, sections_data
    )
    write_report(exec_report, exec_path)
    print(f"        Executive report : {exec_path}")

    # ── Completion summary ────────────────────────────────────
    risk_level, _ = _assess_overall_risk(results)

    print()
    print("=" * 60)
    print("  REPORTS COMPLETE")
    print("=" * 60)
    print(f"  Overall Migration Risk : {risk_level}")
    print()
    print("  Files generated:")
    print(f"    asa_migration_technical.txt")
    print(f"    asa_migration_executive.txt")
    print()
    print("  Transfer both files to your work endpoint and")
    print("  review the technical report for action items")
    print("  before presenting the executive report to the")
    print("  customer.")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
```

---

## How to Use

All six parser files must be in the same directory:
```
asa-migration-parser/
├── asa_parser_p3.py
├── asa_parser_p4.py
├── asa_parser_p5.py
├── asa_parser_p6.py
└── asa_logs.txt
