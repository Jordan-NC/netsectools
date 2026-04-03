# ============================================================
# ASA Migration Parser - Phase 3: Basic Section Parsing
# ============================================================
# PURPOSE:
#   Builds on Phase 2. Extracts and structures data from three
#   foundational sections:
#     - INTERFACE-IP-BRIEF   : Interface inventory
#     - ROUTE                : Routing table
#     - VPN-SESSIONDB-SUMMARY: Active VPN session counts
#
# USAGE:
#   python asa_parser_p3.py <path_to_log_file>
#   Example: python asa_parser_p3.py asa_logs.txt
#
# OUTPUT:
#   Structured, human-readable tables for each parsed section.
#   Flags interfaces that are down, default routes, and
#   active VPN session types relevant to migration planning.
#
# ASSUMPTIONS:
#   INTERFACE-IP-BRIEF:
#     Standard ASA output columns:
#     Interface  IP-Address  OK?  Method  Status  Protocol
#     Example:
#     GigabitEthernet0/0  192.168.1.1  YES  CONFIG  up  up
#     Unassigned interfaces show "unassigned" for IP field.
#
#   ROUTE:
#     Standard ASA route table format:
#     <code> <network> <mask> [AD/metric] via <nexthop>, <iface>
#     Codes: C=connected, S=static, O=OSPF, B=BGP, i=IS-IS
#     Example:
#     S    10.0.0.0 255.0.0.0 [1/0] via 192.168.1.1, outside
#     C    192.168.1.0 255.255.255.0 is directly connected, inside
#
#   VPN-SESSIONDB-SUMMARY:
#     Columnar table format confirmed from Cisco documentation:
#                          Active : Cumulative : Peak Concur : Inactive
#     AnyConnect Client  :   36   :    55555   :     555     :    0
#       SSL/TLS/DTLS     :   36   :    55555   :     555
#     Site-to-Site VPN   :  131   :  7444444   :     300
#       IKEv2 IPsec      :  100   :  5000000   :     240
#       IKEv1 IPsec      :   10   :  2258535   :      70
#     Total Active and Inactive : 153  Total Cumulative : 7400000
#     Device Total VPN Capacity : 2500
#     Device Load : 6%
# ============================================================

import re
import sys
import os
from collections import defaultdict

# ── Expected sections ─────────────────────────────────────────
EXPECTED_SECTIONS = [
    "RUNNING-CONFIG-ALL",
    "RUNNING-CONFIG",
    "INTERFACE",
    "INTERFACE-IP-BRIEF",
    "ACCESS-LIST",
    "ACCESS-LIST-ELEMENTS",
    "RUNNING-CONFIG-ACCESS-LIST",
    "ROUTE",
    "RUNNING-CONFIG-ROUTE",
    "RUNNING-CONFIG-CRYPTO",
    "RUNNING-CONFIG-IP-POOL",
    "VPN-SESSIONDB-SUMMARY",
    "VPN-SESSIONDB-ANYCONNECT",
    "CRYPTO-ISAKMP-SA",
    "CRYPTO-IPSEC-SA",
    "SERVICE-POLICY",
    "RUNNING-CONFIG-LOGGING",
    "LOGGING",
    "RUNNING-CONFIG-AAA",
    "RUNNING-CONFIG-AAA-SERVER",
]

# ── Section header regex ──────────────────────────────────────
SECTION_PATTERN = re.compile(
    r'^!\s*===SECTION:\s*([A-Z0-9_\-]+)\s*===$',
    re.IGNORECASE
)

# ════════════════════════════════════════════════════════════
# SECTION EXTRACTION (from Phase 2)
# ════════════════════════════════════════════════════════════

def extract_sections(filepath):
    """
    Reads the log file and returns a dict of:
      { section_name (str) : [content lines (str)] }
    Identical to Phase 2 extraction logic.
    """
    sections_data = {}
    current_section = None

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            stripped = line.strip()
            match = SECTION_PATTERN.match(stripped)
            if match:
                current_section = match.group(1).upper().strip()
                sections_data[current_section] = []
            elif current_section is not None:
                sections_data[current_section].append(stripped)

    return sections_data


# ════════════════════════════════════════════════════════════
# PARSER 1: INTERFACE-IP-BRIEF
# ════════════════════════════════════════════════════════════
#
# Expected format:
# Interface                IP-Address      OK? Method Status Protocol
# GigabitEthernet0/0       192.168.1.1     YES CONFIG up     up
# Management0/0            unassigned      YES unset  up     up

RE_INTF_BRIEF = re.compile(
    r'^(\S+)\s+'                        # Interface name
    r'([\d\.]+|unassigned)\s+'          # IP address or "unassigned"
    r'(YES|NO)\s+'                      # OK?
    r'(\S+)\s+'                         # Method (CONFIG, DHCP, manual, etc.)
    r'([\w\s]+?)\s{2,}'                 # Status (up, down, admin down)
    r'(up|down)',                       # Protocol
    re.IGNORECASE
)


def parse_interface_brief(lines):
    """
    Parses 'show interface ip brief' output.

    Returns list of dicts:
    {
        'interface': str,
        'ip'       : str,   # IP or 'unassigned'
        'ok'       : str,   # YES / NO
        'method'   : str,
        'status'   : str,   # up / down / admin down
        'protocol' : str    # up / down
    }
    """
    interfaces = []

    for line in lines:
        # Skip column header line
        if line.lower().startswith('interface') and 'ip-address' in line.lower():
            continue
        if not line.strip():
            continue

        match = RE_INTF_BRIEF.match(line)
        if match:
            interfaces.append({
                'interface': match.group(1),
                'ip'       : match.group(2),
                'ok'       : match.group(3),
                'method'   : match.group(4),
                'status'   : match.group(5).strip(),
                'protocol' : match.group(6),
            })

    return interfaces


def print_interface_brief(interfaces):
    """
    Prints interface brief table with migration-relevant flags.
    """
    print("=" * 75)
    print("  INTERFACE INVENTORY  (show interface ip brief)")
    print("=" * 75)

    if not interfaces:
        print("  [WARNING] No interfaces parsed. Check section content.")
        print("  Expected format:")
        print("  GigabitEthernet0/0  192.168.1.1  YES CONFIG up  up")
        return

    print(f"\n  {'INTERFACE':<30} {'IP ADDRESS':<18} {'STATUS':<12}"
          f" {'PROTOCOL':<10} {'FLAGS'}")
    print(f"  {'-'*29} {'-'*17} {'-'*11} {'-'*9} {'-'*20}")

    down_count = 0
    unassigned_count = 0

    for intf in interfaces:
        flags = []

        if intf['status'].lower() != 'up':
            flags.append('DOWN')
            down_count += 1

        if intf['ip'].lower() == 'unassigned':
            flags.append('NO IP')
            unassigned_count += 1

        if 'admin' in intf['status'].lower():
            flags.append('ADMIN-DOWN')

        flag_str = ' | '.join(flags) if flags else ''

        print(f"  {intf['interface']:<30} {intf['ip']:<18} "
              f"{intf['status']:<12} {intf['protocol']:<10} {flag_str}")

    print(f"\n  Total interfaces : {len(interfaces)}")
    print(f"  Down/Admin-down  : {down_count}")
    print(f"  No IP assigned   : {unassigned_count}")

    if down_count > 0:
        print()
        print("  [MIGRATION NOTE] Down interfaces detected.")
        print("  Confirm whether these need to be migrated or")
        print("  decommissioned on the FTD 3110 HA pair.")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 2: ROUTE TABLE
# ════════════════════════════════════════════════════════════
#
# Expected format:
# S    10.0.0.0 255.255.255.0 [1/0] via 192.168.1.1, outside
# C    192.168.1.0 255.255.255.0 is directly connected, inside
# S*   0.0.0.0 0.0.0.0 [1/0] via 10.0.0.1, outside

RE_ROUTE = re.compile(
    r'^([A-Za-z\*\s]{1,5})\s+'         # Route code (C, S, S*, O, B, etc.)
    r'([\d\.]+)\s+'                     # Network address
    r'([\d\.]+)\s+'                     # Subnet mask
    r'(?:\[(\d+/\d+)\]\s+)?'           # Optional [AD/metric]
    r'(?:via\s+([\d\.]+),?\s*)?'        # Optional next-hop IP
    r'(?:is directly connected,\s*)?'   # OR directly connected
    r'(\S+)?'                           # Interface name
)

ROUTE_CODES = {
    'C' : 'Connected',
    'S' : 'Static',
    'S*': 'Static Default',
    'O' : 'OSPF',
    'O*': 'OSPF Default',
    'B' : 'BGP',
    'i' : 'IS-IS',
    'D' : 'EIGRP',
    'EX': 'EIGRP External',
    'L' : 'Local',
}


def parse_route_table(lines):
    """
    Parses 'show route' output.

    Returns list of dicts:
    {
        'code'     : str,   # C, S, S*, O, B, etc.
        'type'     : str,   # Human-readable type
        'network'  : str,
        'mask'     : str,
        'ad_metric': str,   # e.g. '1/0' or '' if connected
        'nexthop'  : str,   # Next-hop IP or '' if connected
        'interface': str,
    }
    """
    routes = []

    for line in lines:
        if not line.strip():
            continue

        # Skip legend and header lines
        if line.lower().startswith(('codes:', 'gateway', 'routing')):
            continue

        match = RE_ROUTE.match(line)
        if match:
            code      = match.group(1).strip()
            network   = match.group(2)
            mask      = match.group(3)
            ad_metric = match.group(4) or ''
            nexthop   = match.group(5) or ''
            interface = match.group(6) or ''
            route_type = ROUTE_CODES.get(code, code)

            routes.append({
                'code'     : code,
                'type'     : route_type,
                'network'  : network,
                'mask'     : mask,
                'ad_metric': ad_metric,
                'nexthop'  : nexthop,
                'interface': interface,
            })

    return routes


def print_route_table(routes):
    """
    Prints route table grouped by type with migration notes.
    """
    print("=" * 80)
    print("  ROUTING TABLE  (show route)")
    print("=" * 80)

    if not routes:
        print("  [WARNING] No routes parsed. Check section content.")
        print("  Expected format:")
        print("  S  10.0.0.0 255.0.0.0 [1/0] via 192.168.1.1, outside")
        return

    grouped = defaultdict(list)
    for r in routes:
        grouped[r['type']].append(r)

    type_order = [
        'Connected', 'Local', 'Static', 'Static Default',
        'OSPF', 'OSPF Default', 'BGP', 'EIGRP', 'IS-IS'
    ]
    all_types = type_order + [t for t in grouped if t not in type_order]

    for rtype in all_types:
        if rtype not in grouped:
            continue

        rlist = grouped[rtype]
        print(f"\n  ── {rtype.upper()} ({len(rlist)} route(s)) " + "─" * 30)
        print(f"  {'NETWORK':<20} {'MASK':<18} {'NEXT-HOP':<18}"
              f" {'INTERFACE':<15} {'AD/METRIC'}")
        print(f"  {'-'*19} {'-'*17} {'-'*17} {'-'*14} {'-'*10}")

        for r in rlist:
            nexthop = r['nexthop'] if r['nexthop'] else 'directly connected'
            print(f"  {r['network']:<20} {r['mask']:<18} "
                  f"{nexthop:<18} {r['interface']:<15} {r['ad_metric']}")

    # Summary
    static_count = (
        len(grouped.get('Static', [])) +
        len(grouped.get('Static Default', []))
    )
    dynamic_types = [
        t for t in grouped
        if t not in ('Connected', 'Local', 'Static', 'Static Default')
    ]

    print(f"\n  Total routes     : {len(routes)}")
    print(f"  Static routes    : {static_count}")

    if dynamic_types:
        print(f"  Dynamic routing  : {', '.join(dynamic_types)}")
        print()
        print("  [MIGRATION NOTE] Dynamic routing protocols detected.")
        print("  These must be reconfigured in FMC — ASA routing config")
        print("  does not migrate automatically via FMT.")
    else:
        print("  Dynamic routing  : None detected")

    # Default route
    default = next(
        (r for r in routes if r['network'] == '0.0.0.0'), None
    )
    if default:
        print(f"\n  [DEFAULT ROUTE]  0.0.0.0/0 via {default['nexthop']}"
              f" ({default['interface']})")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 3: VPN-SESSIONDB-SUMMARY
# ════════════════════════════════════════════════════════════
#
# Confirmed ASA output format:
#
# ---------------------------------------------------------------------------
# VPN Session Summary
# ---------------------------------------------------------------------------
#                          Active : Cumulative : Peak Concur : Inactive
# ----------------------------------------------
# AnyConnect Client        :   36  :     55555  :        555  :        0
#   SSL/TLS/DTLS           :   36  :     55555  :        555
# Site-to-Site VPN         :  131  :   7444444  :        300
#   IKEv2 IPsec            :  100  :   5000000  :        240
#   IKEv1 IPsec            :   10  :   2258535  :         70
# ---------------------------------------------------------------------------
# Total Active and Inactive : 153  Total Cumulative : 7400000
# Device Total VPN Capacity : 2500
# Device Load               : 6%
# ---------------------------------------------------------------------------

# Data rows — parent and child (indented child rows = sub-types)
RE_VPN_DATA_ROW = re.compile(
    r'^(\s*)'                           # Leading whitespace — indent = child
    r'([A-Za-z0-9/\s\(\)\-\.]+?)'      # Session type label
    r'\s*:\s*(\d+)'                     # Active count
    r'\s*:\s*(\d+)'                     # Cumulative count
    r'(?:\s*:\s*(\d+))?'               # Peak Concurrent (optional)
    r'(?:\s*:\s*(\d+))?'               # Inactive (optional)
    r'\s*$'
)

# Total line: Total Active and Inactive : 153  Total Cumulative : 7400000
RE_VPN_TOTAL = re.compile(
    r'Total Active and Inactive\s*:\s*(\d+)'
    r'.*?Total Cumulative\s*:\s*(\d+)',
    re.IGNORECASE
)

# Device Total VPN Capacity : 2500
RE_VPN_CAPACITY = re.compile(
    r'Device Total VPN Capacity\s*:\s*(\d+)',
    re.IGNORECASE
)

# Device Load : 6%
RE_VPN_LOAD = re.compile(
    r'Device Load\s*:\s*(\d+)%',
    re.IGNORECASE
)


def parse_vpn_summary(lines):
    """
    Parses 'show vpn-sessiondb summary' output.

    Returns:
      sessions : list of dicts — one per session type row
      totals   : dict — total active, cumulative, capacity, load
    """
    sessions = []
    totals = {
        'total_active'    : None,
        'total_cumulative': None,
        'capacity'        : None,
        'load_pct'        : None,
    }

    for line in lines:
        # Skip separator lines (all dashes)
        if re.match(r'^-+$', line.strip()):
            continue

        # Skip title line
        if line.strip().lower() == 'vpn session summary':
            continue

        # Skip column header line
        # Header contains "Active" and "Cumulative" but no colon before them
        if ('active' in line.lower() and
                'cumulative' in line.lower() and
                not re.search(r':\s*\d+', line)):
            continue

        # Total line
        total_match = RE_VPN_TOTAL.search(line)
        if total_match:
            totals['total_active']     = int(total_match.group(1))
            totals['total_cumulative'] = int(total_match.group(2))
            continue

        # Capacity line
        cap_match = RE_VPN_CAPACITY.search(line)
        if cap_match:
            totals['capacity'] = int(cap_match.group(1))
            continue

        # Load line
        load_match = RE_VPN_LOAD.search(line)
        if load_match:
            totals['load_pct'] = int(load_match.group(1))
            continue

        # Data row (parent or indented child)
        data_match = RE_VPN_DATA_ROW.match(line)
        if data_match:
            indent   = data_match.group(1)
            label    = data_match.group(2).strip()
            active   = int(data_match.group(3))
            cumul    = int(data_match.group(4))
            peak     = int(data_match.group(5)) if data_match.group(5) else None
            inactive = int(data_match.group(6)) if data_match.group(6) else None
            is_child = len(indent) > 0

            sessions.append({
                'label'     : label,
                'is_child'  : is_child,
                'active'    : active,
                'cumulative': cumul,
                'peak'      : peak,
                'inactive'  : inactive,
            })

    return sessions, totals


def print_vpn_summary(sessions, totals):
    """
    Prints VPN session summary with migration planning notes.
    """
    print("=" * 70)
    print("  VPN SESSION SUMMARY  (show vpn-sessiondb summary)")
    print("=" * 70)

    if not sessions and totals['total_active'] is None:
        print("  [WARNING] No VPN session data parsed.")
        print("  Verify section content matches expected ASA output format.")
        return

    # ── Session table ─────────────────────────────────────────
    print(f"\n  {'SESSION TYPE':<35} {'ACTIVE':>8} {'CUMULATIVE':>12}"
          f" {'PEAK':>8} {'INACTIVE':>10}")
    print(f"  {'-'*34} {'-'*8} {'-'*12} {'-'*8} {'-'*10}")

    for s in sessions:
        label    = ('  ' + s['label']) if s['is_child'] else s['label']
        active   = str(s['active'])
        cumul    = f"{s['cumulative']:,}"
        peak     = str(s['peak'])     if s['peak']     is not None else '—'
        inactive = str(s['inactive']) if s['inactive'] is not None else '—'

        print(f"  {label:<35} {active:>8} {cumul:>12} {peak:>8} {inactive:>10}")

    # ── Totals block ──────────────────────────────────────────
    print(f"\n  {'-'*70}")

    if totals['total_active'] is not None:
        print(f"  Total Active + Inactive  : {totals['total_active']}")
    if totals['total_cumulative'] is not None:
        print(f"  Total Cumulative         : {totals['total_cumulative']:,}")
    if totals['capacity'] is not None:
        print(f"  Device VPN Capacity      : {totals['capacity']}")
    if totals['load_pct'] is not None:
        print(f"  Device Load              : {totals['load_pct']}%")

        if totals['load_pct'] >= 80:
            print()
            print("  [WARNING] Device load >= 80%. Verify the FTD 3110 HA")
            print("  pair is sized to handle this VPN load before cutover.")

    # ── Migration notes ───────────────────────────────────────
    print(f"\n  {'='*70}")
    print("  MIGRATION NOTES")
    print(f"  {'='*70}")

    labels_lower = [s['label'].lower() for s in sessions]

    has_anyconnect = any('anyconnect' in l for l in labels_lower)
    has_s2s        = any('site-to-site' in l for l in labels_lower)
    has_ikev1      = any('ikev1' in l for l in labels_lower)
    has_ikev2      = any('ikev2' in l for l in labels_lower)

    anyconnect_active = next(
        (s['active'] for s in sessions
         if 'anyconnect client' in s['label'].lower()
         and not s['is_child']),
        0
    )
    s2s_active = next(
        (s['active'] for s in sessions
         if 'site-to-site' in s['label'].lower()
         and not s['is_child']),
        0
    )

    if has_anyconnect:
        print(f"\n  [ANYCONNECT]  {anyconnect_active} active session(s)")
        print("  RA VPN must be fully configured in FMC prior to cutover.")
        print("  Active sessions will disconnect during migration.")
        print("  Plan a maintenance window or coordinate with end users.")

    if has_s2s:
        print(f"\n  [SITE-TO-SITE]  {s2s_active} active tunnel(s)")
        print("  All S2S tunnels will drop during FTD cutover.")
        print("  Notify remote peer administrators before migration.")

    if has_ikev1:
        print()
        print("  [IKEv1 DETECTED]")
        print("  FTD supports IKEv1 but Cisco recommends migrating to IKEv2.")
        print("  Review RUNNING-CONFIG-CRYPTO for weak proposals:")
        print("  DES, 3DES, MD5, DH group 1/2/5 — FTD may reject these.")

    if has_ikev2:
        print()
        print("  [IKEv2 DETECTED]")
        print("  IKEv2 migrates cleanly to FTD.")
        print("  Verify crypto proposals in RUNNING-CONFIG-CRYPTO section.")

    if not has_anyconnect and not has_s2s:
        print("\n  [INFO] No AnyConnect or Site-to-Site sessions detected.")
        print("  Confirm VPN is not in use or was not active at capture time.")

    print()


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def print_header():
    print()
    print("=" * 70)
    print("  ASA MIGRATION PARSER — PHASE 3")
    print("  Sections: Interface Brief | Routes | VPN Summary")
    print("=" * 70)
    print()


def main():
    # ── Argument handling ──────────────────────────────────────
    if len(sys.argv) != 2:
        print("Usage: python asa_parser_p3.py <path_to_log_file>")
        print("Example: python asa_parser_p3.py asa_logs.txt")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.isfile(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    if os.path.getsize(filepath) == 0:
        print(f"[ERROR] File is empty: {filepath}")
        sys.exit(1)

    print_header()

    # ── Extract all sections ───────────────────────────────────
    sections_data = extract_sections(filepath)

    # ── Parse and print: Interface IP Brief ───────────────────
    intf_lines = sections_data.get("INTERFACE-IP-BRIEF", [])
    if intf_lines:
        interfaces = parse_interface_brief(intf_lines)
        print_interface_brief(interfaces)
    else:
        print("  [SKIPPED] INTERFACE-IP-BRIEF — section empty or not found.\n")

    # ── Parse and print: Route Table ──────────────────────────
    route_lines = sections_data.get("ROUTE", [])
    if route_lines:
        routes = parse_route_table(route_lines)
        print_route_table(routes)
    else:
        print("  [SKIPPED] ROUTE — section empty or not found.\n")

    # ── Parse and print: VPN Session Summary ──────────────────
    vpn_lines = sections_data.get("VPN-SESSIONDB-SUMMARY", [])
    if vpn_lines:
        sessions, totals = parse_vpn_summary(vpn_lines)
        print_vpn_summary(sessions, totals)
    else:
        print("  [SKIPPED] VPN-SESSIONDB-SUMMARY — section empty or not found.\n")


if __name__ == "__main__":
    main()
