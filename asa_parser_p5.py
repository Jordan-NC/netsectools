# ============================================================
# ASA Migration Parser - Phase 5: NAT Parsing
# ============================================================
# PURPOSE:
#   Parses NAT configuration from the RUNNING-CONFIG-ALL
#   section. Covers both NAT styles ASA supports:
#
#   Style 1 — Twice NAT (Policy NAT):
#     Written directly in global config outside any object.
#     Translates both source and destination simultaneously.
#     Used for VPN hairpinning, identity NAT, and complex
#     policy-based translations.
#     Format:
#       nat (<src>,<dst>) source <action> <obj> <obj>
#         [destination <action> <obj> <obj>]
#         [no-proxy-arp] [route-lookup] [inactive]
#         [description <text>]
#
#   Style 2 — Object NAT:
#     Written inside an object network block.
#     Simpler one-directional translations.
#     Used for standard PAT and static NAT.
#     Format:
#       object network <name>
#        host <ip> | subnet <ip> <mask> | range <ip> <ip>
#        [description <text>]
#        nat (<src>,<dst>) <action> <translated>
#          [no-proxy-arp] [route-lookup]
#
#   Also parses:
#     - object network blocks (host, subnet, range, description)
#     - object-group network blocks (members, description)
#     - NAT-related object identification via description text
#
# USAGE:
#   python asa_parser_p5.py <path_to_log_file>
#
# SOURCE SECTION:
#   Primary  : RUNNING-CONFIG-ALL
#   Fallback : RUNNING-CONFIG
#
# FTD MIGRATION NOTES GENERATED FOR:
#   - Inactive NAT rules (not supported on FTD)
#   - Dynamic interface PAT (requires FMC NAT policy)
#   - Twice NAT rules (must be manually recreated in FMC)
#   - Object NAT rules (can use FMT but verify post-migration)
#   - no-proxy-arp and route-lookup flags
#   - NAT rule count and complexity assessment
#
# THREE-LAYER PARSING ARCHITECTURE:
#   Layer 1 — Full match against documented ASA NAT syntax
#   Layer 2 — Partial match — line looks NAT-related but
#             didn't fully parse — flagged [PARTIAL]
#   Layer 3 — Unmatched capture — nothing silently dropped
# ============================================================

import re
import sys
import os
from collections import defaultdict


# ════════════════════════════════════════════════════════════
# SECTION HEADER PATTERN
# ════════════════════════════════════════════════════════════

SECTION_PATTERN = re.compile(
    r'^!\s*===SECTION:\s*([A-Z0-9_\-]+)\s*===$',
    re.IGNORECASE
)


# ════════════════════════════════════════════════════════════
# SECTION EXTRACTION
# ════════════════════════════════════════════════════════════

def extract_sections(filepath):
    """
    Reads the log file and returns:
      { section_name: [raw lines with leading whitespace preserved] }
    """
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
# NAT REGEX PATTERNS
# ════════════════════════════════════════════════════════════

# ── Twice NAT (global, outside any object block) ──────────────
#
# Full documented syntax:
#   nat (<src-iface>,<dst-iface>) [line <n>] [after-auto]
#     source <static|dynamic> <real> <mapped>
#     [destination <static|dynamic> <real> <mapped>]
#     [dns] [no-proxy-arp] [route-lookup] [inactive]
#     [unidirectional] [description <text>]
#
# Interface pair is always (<word>,<word>) — may have spaces
# after comma. Both interface names may contain hyphens,
# underscores, digits.

RE_TWICE_NAT = re.compile(
    r'^nat\s+'
    r'\(\s*(\S+)\s*,\s*(\S+)\s*\)'     # (src-iface, dst-iface)
    r'(?:\s+line\s+(\d+))?'            # optional line number
    r'(?:\s+(after-auto))?'            # optional after-auto
    r'\s+source\s+'
    r'(static|dynamic)\s+'             # source action
    r'(\S+)\s+'                        # source real obj
    r'(\S+)'                           # source mapped obj
    r'(.*?)$',                         # rest (destination + options)
    re.IGNORECASE
)

# ── Object NAT (inside object network block) ──────────────────
#
# Full documented syntax:
#   nat (<src-iface>,<dst-iface>)
#     <static|dynamic> <mapped-ip|object|interface>
#     [<mapped-mask>] [dns] [no-proxy-arp] [route-lookup]
#     [net-to-net] [service <protocol> <real> <mapped>]

RE_OBJECT_NAT = re.compile(
    r'^\s+nat\s+'
    r'\(\s*(\S+)\s*,\s*(\S+)\s*\)'     # (src-iface, dst-iface)
    r'\s+(static|dynamic)\s+'          # action
    r'(\S+)'                           # mapped (ip, object name, or 'interface')
    r'(.*?)$',                         # rest (mask, options)
    re.IGNORECASE
)

# ── object network block header ───────────────────────────────
RE_OBJ_NETWORK = re.compile(
    r'^object network\s+(\S+)',
    re.IGNORECASE
)

# Object network sub-commands (indented)
RE_OBJ_HOST    = re.compile(r'^\s+host\s+(\S+)', re.IGNORECASE)
RE_OBJ_SUBNET  = re.compile(r'^\s+subnet\s+(\S+)\s+(\S+)', re.IGNORECASE)
RE_OBJ_RANGE   = re.compile(r'^\s+range\s+(\S+)\s+(\S+)', re.IGNORECASE)
RE_OBJ_FQDN    = re.compile(r'^\s+fqdn\s+(\S+)', re.IGNORECASE)
RE_OBJ_DESC    = re.compile(r'^\s+description\s+(.*)', re.IGNORECASE)

# ── object-group network block header ────────────────────────
RE_OBJ_GRP_NETWORK = re.compile(
    r'^object-group network\s+(\S+)',
    re.IGNORECASE
)

# Object-group sub-commands (indented)
RE_GRP_NET_OBJ  = re.compile(
    r'^\s+network-object\s+object\s+(\S+)',
    re.IGNORECASE
)
RE_GRP_NET_HOST = re.compile(
    r'^\s+network-object\s+host\s+(\S+)',
    re.IGNORECASE
)
RE_GRP_NET_CIDR = re.compile(
    r'^\s+network-object\s+(\S+)\s+(\S+)',
    re.IGNORECASE
)
RE_GRP_DESC     = re.compile(r'^\s+description\s+(.*)', re.IGNORECASE)
RE_GRP_GRP      = re.compile(
    r'^\s+group-object\s+(\S+)',
    re.IGNORECASE
)

# ── NAT option flags ──────────────────────────────────────────
RE_NO_PROXY_ARP  = re.compile(r'\bno-proxy-arp\b', re.IGNORECASE)
RE_ROUTE_LOOKUP  = re.compile(r'\broute-lookup\b', re.IGNORECASE)
RE_INACTIVE_FLAG = re.compile(r'\binactive\b', re.IGNORECASE)
RE_UNIDIRECT     = re.compile(r'\bunidirectional\b', re.IGNORECASE)
RE_DNS_FLAG      = re.compile(r'\bdns\b', re.IGNORECASE)
RE_NET_TO_NET    = re.compile(r'\bnet-to-net\b', re.IGNORECASE)
RE_DESCRIPTION   = re.compile(r'\bdescription\s+(.*)', re.IGNORECASE)

# ── Destination clause inside Twice NAT rest ─────────────────
RE_DEST_CLAUSE = re.compile(
    r'\bdestination\s+(static|dynamic)\s+(\S+)\s+(\S+)',
    re.IGNORECASE
)

# ── Service clause inside NAT rest ───────────────────────────
RE_SERVICE_CLAUSE = re.compile(
    r'\bservice\s+(\S+)\s+(\S+)\s+(\S+)',
    re.IGNORECASE
)

# ── Partial match triggers ────────────────────────────────────
# Any line starting with 'nat' at column 0 (Twice NAT attempt)
RE_NAT_PARTIAL = re.compile(r'^nat\s+', re.IGNORECASE)
# Any indented 'nat' line (Object NAT attempt)
RE_NAT_OBJ_PARTIAL = re.compile(r'^\s+nat\s+', re.IGNORECASE)

# NAT-related description keyword
RE_NAT_DESC_KEYWORD = re.compile(r'\bnat\b', re.IGNORECASE)


# ════════════════════════════════════════════════════════════
# HELPER: PARSE OPTION FLAGS FROM REST STRING
# ════════════════════════════════════════════════════════════

def parse_nat_options(rest):
    """
    Extracts all NAT option flags and clauses from the
    remainder string after the core NAT tokens.

    Returns dict of parsed options.
    """
    opts = {
        'no_proxy_arp'  : bool(RE_NO_PROXY_ARP.search(rest)),
        'route_lookup'  : bool(RE_ROUTE_LOOKUP.search(rest)),
        'inactive'      : bool(RE_INACTIVE_FLAG.search(rest)),
        'unidirectional': bool(RE_UNIDIRECT.search(rest)),
        'dns'           : bool(RE_DNS_FLAG.search(rest)),
        'net_to_net'    : bool(RE_NET_TO_NET.search(rest)),
        'description'   : None,
        'dst_action'    : None,
        'dst_real'      : None,
        'dst_mapped'    : None,
        'service_proto' : None,
        'service_real'  : None,
        'service_mapped': None,
    }

    # Destination clause
    dm = RE_DEST_CLAUSE.search(rest)
    if dm:
        opts['dst_action'] = dm.group(1).lower()
        opts['dst_real']   = dm.group(2)
        opts['dst_mapped'] = dm.group(3)

    # Service clause
    sm = RE_SERVICE_CLAUSE.search(rest)
    if sm:
        opts['service_proto']  = sm.group(1)
        opts['service_real']   = sm.group(2)
        opts['service_mapped'] = sm.group(3)

    # Description (inline on nat line)
    desc_m = RE_DESCRIPTION.search(rest)
    if desc_m:
        # Strip trailing option keywords from description
        desc_text = desc_m.group(1).strip()
        for kw in ['no-proxy-arp', 'route-lookup', 'inactive',
                   'unidirectional', 'dns', 'net-to-net']:
            desc_text = re.sub(
                rf'\s+{re.escape(kw)}.*$', '', desc_text,
                flags=re.IGNORECASE
            ).strip()
        opts['description'] = desc_text if desc_text else None

    return opts


# ════════════════════════════════════════════════════════════
# MAIN NAT PARSER
# ════════════════════════════════════════════════════════════

def parse_nat(lines):
    """
    Parses NAT configuration from RUNNING-CONFIG-ALL lines.

    Uses three-layer architecture:
      Layer 1 — Full match
      Layer 2 — Partial match (NAT-like but unparseable)
      Layer 3 — Unmatched capture

    Returns:
      twice_nat_rules  : [ rule_dict ]
      object_nat_rules : [ rule_dict ]
      network_objects  : { name: object_dict }
      network_groups   : { name: group_dict }
      nat_partials     : [ line ]
      unmatched_nat    : [ line ]

    twice_nat rule_dict:
    {
        'src_iface'     : str,
        'dst_iface'     : str,
        'line_num'      : str or None,
        'after_auto'    : bool,
        'src_action'    : str,   # static / dynamic
        'src_real'      : str,
        'src_mapped'    : str,
        'dst_action'    : str or None,
        'dst_real'      : str or None,
        'dst_mapped'    : str or None,
        'no_proxy_arp'  : bool,
        'route_lookup'  : bool,
        'inactive'      : bool,
        'unidirectional': bool,
        'dns'           : bool,
        'service_proto' : str or None,
        'service_real'  : str or None,
        'service_mapped': str or None,
        'description'   : str or None,
        'raw'           : str,
    }

    object_nat rule_dict:
    {
        'object_name'   : str,
        'src_iface'     : str,
        'dst_iface'     : str,
        'action'        : str,   # static / dynamic
        'mapped'        : str,   # ip, object name, or 'interface'
        'mapped_mask'   : str or None,
        'no_proxy_arp'  : bool,
        'route_lookup'  : bool,
        'dns'           : bool,
        'net_to_net'    : bool,
        'service_proto' : str or None,
        'service_real'  : str or None,
        'service_mapped': str or None,
        'raw'           : str,
    }

    network_objects dict:
    {
        'name'        : str,
        'type'        : str,   # host / subnet / range / fqdn / empty
        'value'       : str,   # IP, network/mask, range, fqdn
        'description' : str or None,
        'has_nat'     : bool,
        'nat_desc_ref': bool,  # description contains NAT keyword
    }

    network_groups dict:
    {
        'name'        : str,
        'description' : str or None,
        'members'     : [ member_dict ],
        'nat_desc_ref': bool,
    }
    """
    twice_nat_rules  = []
    object_nat_rules = []
    network_objects  = {}
    network_groups   = {}
    nat_partials     = []
    unmatched_nat    = []

    # Block state
    current_obj_network = None
    current_obj_group   = None

    # Lines we care about — NAT lines, object blocks, object-group blocks
    # Everything else is silently passed (routing, aaa, logging, etc.)
    # We only capture unmatched lines that look NAT-related
    NAT_CONTEXT_KEYWORDS = {
        'nat', 'object', 'object-group', 'network-object',
        'group-object', 'host', 'subnet', 'range', 'fqdn',
        'description',
    }

    def line_looks_nat_related(s):
        first_word = s.split()[0].lower() if s.split() else ''
        return first_word in NAT_CONTEXT_KEYWORDS

    for line in lines:
        if not line.strip():
            # Blank line ends current block context
            # but we don't reset — indented sub-lines
            # may follow after a blank in some ASA versions
            continue

        stripped = line.strip()
        first_word = stripped.split()[0].lower() if stripped.split() else ''

        # ── object network header ─────────────────────────────
        m = RE_OBJ_NETWORK.match(stripped)
        if m:
            current_obj_group = None
            name = m.group(1)
            current_obj_network = {
                'name'        : name,
                'type'        : 'empty',
                'value'       : None,
                'description' : None,
                'has_nat'     : False,
                'nat_desc_ref': False,
            }
            network_objects[name] = current_obj_network
            continue

        # ── object network sub-commands ───────────────────────
        if current_obj_network is not None:
            is_indented = line.startswith(' ') or line.startswith('\t')

            if is_indented:
                # host
                m = RE_OBJ_HOST.match(line)
                if m:
                    current_obj_network['type']  = 'host'
                    current_obj_network['value'] = m.group(1)
                    continue

                # subnet
                m = RE_OBJ_SUBNET.match(line)
                if m:
                    current_obj_network['type']  = 'subnet'
                    current_obj_network['value'] = (
                        f"{m.group(1)} {m.group(2)}"
                    )
                    continue

                # range
                m = RE_OBJ_RANGE.match(line)
                if m:
                    current_obj_network['type']  = 'range'
                    current_obj_network['value'] = (
                        f"{m.group(1)}-{m.group(2)}"
                    )
                    continue

                # fqdn
                m = RE_OBJ_FQDN.match(line)
                if m:
                    current_obj_network['type']  = 'fqdn'
                    current_obj_network['value'] = m.group(1)
                    continue

                # description
                m = RE_OBJ_DESC.match(line)
                if m:
                    desc = m.group(1).strip()
                    current_obj_network['description'] = desc
                    if RE_NAT_DESC_KEYWORD.search(desc):
                        current_obj_network['nat_desc_ref'] = True
                    continue

                # Object NAT line (Layer 1)
                m = RE_OBJECT_NAT.match(line)
                if m:
                    current_obj_network['has_nat'] = True
                    rest = m.group(5) or ''
                    opts = parse_nat_options(rest)

                    # Extract mapped mask if present
                    # Mapped mask appears immediately after mapped token
                    # before any option keywords
                    mapped_mask = None
                    rest_tokens = rest.strip().split()
                    option_keywords = {
                        'no-proxy-arp', 'route-lookup', 'inactive',
                        'dns', 'net-to-net', 'unidirectional',
                        'description', 'service',
                    }
                    if rest_tokens and \
                       rest_tokens[0].lower() not in option_keywords:
                        # First token after mapped is a mask
                        candidate = rest_tokens[0]
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', candidate):
                            mapped_mask = candidate

                    object_nat_rules.append({
                        'object_name'   : current_obj_network['name'],
                        'src_iface'     : m.group(1),
                        'dst_iface'     : m.group(2),
                        'action'        : m.group(3).lower(),
                        'mapped'        : m.group(4),
                        'mapped_mask'   : mapped_mask,
                        'no_proxy_arp'  : opts['no_proxy_arp'],
                        'route_lookup'  : opts['route_lookup'],
                        'dns'           : opts['dns'],
                        'net_to_net'    : opts['net_to_net'],
                        'service_proto' : opts['service_proto'],
                        'service_real'  : opts['service_real'],
                        'service_mapped': opts['service_mapped'],
                        'raw'           : stripped,
                    })
                    continue

                # Object NAT partial (Layer 2)
                if RE_NAT_OBJ_PARTIAL.match(line):
                    nat_partials.append(stripped)
                    continue

                # Any other indented line inside object network
                # — not NAT-related, skip silently
                continue

            else:
                # Non-indented = object block ended
                current_obj_network = None
                # Fall through to process this line normally

        # ── object-group network header ───────────────────────
        m = RE_OBJ_GRP_NETWORK.match(stripped)
        if m:
            current_obj_network = None
            name = m.group(1)
            current_obj_group = {
                'name'        : name,
                'description' : None,
                'members'     : [],
                'nat_desc_ref': False,
            }
            network_groups[name] = current_obj_group
            continue

        # ── object-group sub-commands ─────────────────────────
        if current_obj_group is not None:
            is_indented = line.startswith(' ') or line.startswith('\t')

            if is_indented:
                # description
                m = RE_GRP_DESC.match(line)
                if m:
                    desc = m.group(1).strip()
                    current_obj_group['description'] = desc
                    if RE_NAT_DESC_KEYWORD.search(desc):
                        current_obj_group['nat_desc_ref'] = True
                    continue

                # network-object object <name>
                m = RE_GRP_NET_OBJ.match(line)
                if m:
                    current_obj_group['members'].append({
                        'type' : 'object',
                        'value': m.group(1),
                    })
                    continue

                # network-object host <ip>
                m = RE_GRP_NET_HOST.match(line)
                if m:
                    current_obj_group['members'].append({
                        'type' : 'host',
                        'value': m.group(1),
                    })
                    continue

                # network-object <ip> <mask>
                m = RE_GRP_NET_CIDR.match(line)
                if m:
                    current_obj_group['members'].append({
                        'type' : 'network',
                        'value': f"{m.group(1)} {m.group(2)}",
                    })
                    continue

                # group-object <name> (nested group)
                m = RE_GRP_GRP.match(line)
                if m:
                    current_obj_group['members'].append({
                        'type' : 'group',
                        'value': m.group(1),
                    })
                    continue

                # Any other indented line — skip silently
                continue

            else:
                # Non-indented = group block ended
                current_obj_group = None
                # Fall through

        # ── Twice NAT (global, non-indented nat line) ─────────
        # Layer 1: Full match
        m = RE_TWICE_NAT.match(stripped)
        if m:
            rest = m.group(8) or ''
            opts = parse_nat_options(rest)

            twice_nat_rules.append({
                'src_iface'     : m.group(1),
                'dst_iface'     : m.group(2),
                'line_num'      : m.group(3),
                'after_auto'    : bool(m.group(4)),
                'src_action'    : m.group(5).lower(),
                'src_real'      : m.group(6),
                'src_mapped'    : m.group(7),
                'dst_action'    : opts['dst_action'],
                'dst_real'      : opts['dst_real'],
                'dst_mapped'    : opts['dst_mapped'],
                'no_proxy_arp'  : opts['no_proxy_arp'],
                'route_lookup'  : opts['route_lookup'],
                'inactive'      : opts['inactive'],
                'unidirectional': opts['unidirectional'],
                'dns'           : opts['dns'],
                'service_proto' : opts['service_proto'],
                'service_real'  : opts['service_real'],
                'service_mapped': opts['service_mapped'],
                'description'   : opts['description'],
                'raw'           : stripped,
            })
            continue

        # Layer 2: Partial match — looks like a NAT line
        if RE_NAT_PARTIAL.match(stripped):
            nat_partials.append(stripped)
            continue

        # For all other lines — only capture as unmatched if
        # they look NAT-related. Everything else (routing, aaa,
        # crypto, etc.) in RUNNING-CONFIG-ALL is intentionally
        # skipped — we are only parsing NAT context here.
        if line_looks_nat_related(stripped):
            unmatched_nat.append(stripped)

    return (
        twice_nat_rules,
        object_nat_rules,
        network_objects,
        network_groups,
        nat_partials,
        unmatched_nat,
    )


# ════════════════════════════════════════════════════════════
# PRINT: TWICE NAT
# ════════════════════════════════════════════════════════════

def print_twice_nat(twice_nat_rules):
    """Prints Twice NAT (Policy NAT) analysis."""

    print(f"\n  ── TWICE NAT / POLICY NAT ({len(twice_nat_rules)} rules) "
          + "─" * 30)

    if not twice_nat_rules:
        print("     None detected.")
        return

    # Categorize
    inactive    = [r for r in twice_nat_rules if r['inactive']]
    with_dest   = [r for r in twice_nat_rules if r['dst_action']]
    after_auto  = [r for r in twice_nat_rules if r['after_auto']]
    static_src  = [r for r in twice_nat_rules
                   if r['src_action'] == 'static']
    dynamic_src = [r for r in twice_nat_rules
                   if r['src_action'] == 'dynamic']
    with_svc    = [r for r in twice_nat_rules if r['service_proto']]
    unidirect   = [r for r in twice_nat_rules if r['unidirectional']]

    print(f"     Total Twice NAT rules  : {len(twice_nat_rules)}")
    print(f"     Static source          : {len(static_src)}")
    print(f"     Dynamic source         : {len(dynamic_src)}")
    print(f"     With destination NAT   : {len(with_dest)}")
    print(f"     After-auto             : {len(after_auto)}")
    print(f"     With service clause    : {len(with_svc)}")
    print(f"     Unidirectional         : {len(unidirect)}")
    print(f"     Inactive rules         : {len(inactive)}")

    # ── Inactive rules detail ─────────────────────────────────
    if inactive:
        print(f"\n     [FLAG] INACTIVE TWICE NAT RULES"
              f" ({len(inactive)}) — not supported on FTD:")
        for r in inactive:
            print(f"       ({r['src_iface']},{r['dst_iface']})"
                  f" source {r['src_action']}"
                  f" {r['src_real']} -> {r['src_mapped']}")

    # ── Interface pair inventory ──────────────────────────────
    print(f"\n     INTERFACE PAIR INVENTORY")
    print(f"     " + "=" * 60)

    pair_counts = defaultdict(int)
    for r in twice_nat_rules:
        pair = f"({r['src_iface']},{r['dst_iface']})"
        pair_counts[pair] += 1

    print(f"     {'INTERFACE PAIR':<40} {'RULE COUNT':>10}")
    print(f"     {'-'*39} {'-'*10}")
    for pair, count in sorted(
        pair_counts.items(), key=lambda x: -x[1]
    ):
        print(f"     {pair:<40} {count:>10}")

    # ── Rule type breakdown ───────────────────────────────────
    print(f"\n     RULE DETAIL")
    print(f"     " + "=" * 60)
    print(f"     {'#':<5} {'IFACE PAIR':<25} {'SRC ACTION':<10}"
          f" {'SRC REAL':<20} {'SRC MAPPED':<20} {'FLAGS'}")
    print(f"     {'-'*4} {'-'*24} {'-'*9} {'-'*19}"
          f" {'-'*19} {'-'*15}")

    for i, r in enumerate(twice_nat_rules, 1):
        pair  = f"({r['src_iface']},{r['dst_iface']})"
        flags = []
        if r['inactive']:      flags.append('INACTIVE')
        if r['no_proxy_arp']:  flags.append('no-proxy-arp')
        if r['route_lookup']:  flags.append('route-lookup')
        if r['dns']:           flags.append('dns')
        if r['unidirectional']:flags.append('unidirect')
        if r['after_auto']:    flags.append('after-auto')
        if r['dst_action']:    flags.append('2x-NAT')
        if r['service_proto']: flags.append(f"svc:{r['service_proto']}")
        flag_str = ' '.join(flags)

        print(f"     {i:<5} {pair:<25} {r['src_action']:<10}"
              f" {r['src_real']:<20} {r['src_mapped']:<20}"
              f" {flag_str}")

        # Print destination NAT clause if present
        if r['dst_action']:
            print(f"            destination {r['dst_action']}"
                  f" {r['dst_real']} -> {r['dst_mapped']}")

    # ── Migration notes ───────────────────────────────────────
    print(f"\n     TWICE NAT MIGRATION NOTES")
    print(f"     " + "=" * 60)

    print(f"     * Twice NAT rules require manual recreation in FMC.")
    print(f"       FMT does not migrate Twice NAT automatically.")
    print(f"       Navigate: FMC > Devices > NAT > Add Rule > Manual NAT")

    if inactive:
        print(f"\n     * [BLOCKER] {len(inactive)} inactive rule(s) must be")
        print(f"       removed — FTD does not support 'inactive' in NAT.")

    if with_dest:
        print(f"\n     * {len(with_dest)} rule(s) use destination NAT.")
        print(f"       These are the most complex rules — verify traffic")
        print(f"       flow and object references carefully in FMC.")

    if dynamic_src:
        print(f"\n     * {len(dynamic_src)} dynamic source NAT rule(s).")
        print(f"       Verify PAT pool or interface PAT config in FMC.")

    if after_auto:
        print(f"\n     * {len(after_auto)} after-auto rule(s) detected.")
        print(f"       In FMC these map to Section 3 of the NAT policy.")
        print(f"       Default (non-after-auto) rules map to Section 1.")

    if unidirect:
        print(f"\n     * {len(unidirect)} unidirectional rule(s).")
        print(f"       FTD supports unidirectional NAT — verify the")
        print(f"       'Do not translate' option is set correctly in FMC.")
    print()


# ════════════════════════════════════════════════════════════
# PRINT: OBJECT NAT
# ════════════════════════════════════════════════════════════

def print_object_nat(object_nat_rules, network_objects):
    """Prints Object NAT analysis."""

    print(f"\n  ── OBJECT NAT ({len(object_nat_rules)} rules) "
          + "─" * 48)

    if not object_nat_rules:
        print("     None detected.")
        return

    # Categorize
    static_rules  = [r for r in object_nat_rules
                     if r['action'] == 'static']
    dynamic_rules = [r for r in object_nat_rules
                     if r['action'] == 'dynamic']
    pat_iface     = [r for r in object_nat_rules
                     if r['mapped'].lower() == 'interface']
    with_svc      = [r for r in object_nat_rules if r['service_proto']]

    print(f"     Total Object NAT rules : {len(object_nat_rules)}")
    print(f"     Static                 : {len(static_rules)}")
    print(f"     Dynamic                : {len(dynamic_rules)}")
    print(f"     Dynamic interface PAT  : {len(pat_iface)}")
    print(f"     With service clause    : {len(with_svc)}")

    # ── Interface pair inventory ──────────────────────────────
    print(f"\n     INTERFACE PAIR INVENTORY")
    print(f"     " + "=" * 60)

    pair_counts = defaultdict(int)
    for r in object_nat_rules:
        pair = f"({r['src_iface']},{r['dst_iface']})"
        pair_counts[pair] += 1

    print(f"     {'INTERFACE PAIR':<40} {'RULE COUNT':>10}")
    print(f"     {'-'*39} {'-'*10}")
    for pair, count in sorted(
        pair_counts.items(), key=lambda x: -x[1]
    ):
        print(f"     {pair:<40} {count:>10}")

    # ── Rule detail table ─────────────────────────────────────
    print(f"\n     RULE DETAIL")
    print(f"     " + "=" * 60)
    print(f"     {'#':<5} {'OBJECT':<25} {'IFACE PAIR':<22}"
          f" {'ACTION':<10} {'MAPPED TO':<20} {'FLAGS'}")
    print(f"     {'-'*4} {'-'*24} {'-'*21} {'-'*9}"
          f" {'-'*19} {'-'*15}")

    for i, r in enumerate(object_nat_rules, 1):
        pair  = f"({r['src_iface']},{r['dst_iface']})"
        flags = []
        if r['no_proxy_arp']:  flags.append('no-proxy-arp')
        if r['route_lookup']:  flags.append('route-lookup')
        if r['dns']:           flags.append('dns')
        if r['net_to_net']:    flags.append('net-to-net')
        if r['service_proto']: flags.append(f"svc:{r['service_proto']}")
        flag_str = ' '.join(flags)

        mapped = r['mapped']
        if r['mapped_mask']:
            mapped += f" {r['mapped_mask']}"

        print(f"     {i:<5} {r['object_name']:<25} {pair:<22}"
              f" {r['action']:<10} {mapped:<20} {flag_str}")

    # ── Dynamic interface PAT detail ──────────────────────────
    if pat_iface:
        print(f"\n     DYNAMIC INTERFACE PAT RULES ({len(pat_iface)})")
        print(f"     " + "=" * 60)
        print(f"     These rules perform PAT using the interface IP.")
        print(f"     In FMC: Add Object NAT rule > Dynamic >"
              f" Translated Addr = Interface.")
        for r in pat_iface:
            obj = network_objects.get(r['object_name'], {})
            obj_val = obj.get('value', '(unknown)')
            obj_type = obj.get('type', 'unknown')
            print(f"       Object: {r['object_name']}"
                  f" ({obj_type}: {obj_val})"
                  f" -> interface ({r['src_iface']},{r['dst_iface']})")

    # ── Migration notes ───────────────────────────────────────
    print(f"\n     OBJECT NAT MIGRATION NOTES")
    print(f"     " + "=" * 60)
    print(f"     * Object NAT rules can be migrated via FMT.")
    print(f"       Verify all referenced network objects exist")
    print(f"       in FMC before running FMT.")

    if pat_iface:
        print(f"\n     * {len(pat_iface)} interface PAT rule(s) detected.")
        print(f"       Verify the correct interface is selected in FMC")
        print(f"       NAT policy post-migration.")

    if with_svc:
        print(f"\n     * {len(with_svc)} rule(s) include service clauses.")
        print(f"       FTD supports service NAT — verify port translation")
        print(f"       is configured correctly in FMC.")
    print()


# ════════════════════════════════════════════════════════════
# PRINT: NETWORK OBJECTS
# ════════════════════════════════════════════════════════════

def print_network_objects(network_objects, network_groups):
    """Prints network object and object-group inventory."""

    print(f"\n  ── NETWORK OBJECT INVENTORY"
          f" ({len(network_objects)} objects) " + "─" * 30)

    if not network_objects:
        print("     None detected.")
    else:
        # Summary by type
        type_counts = defaultdict(int)
        for obj in network_objects.values():
            type_counts[obj['type']] += 1

        nat_objects     = [o for o in network_objects.values()
                           if o['has_nat']]
        nat_desc_refs   = [o for o in network_objects.values()
                           if o['nat_desc_ref'] and not o['has_nat']]

        print(f"     Object type breakdown:")
        for otype, count in sorted(
            type_counts.items(), key=lambda x: -x[1]
        ):
            print(f"       {otype:<15} : {count}")

        print(f"\n     Objects with inline NAT  : {len(nat_objects)}")
        print(f"     NAT-referenced by desc   : {len(nat_desc_refs)}")

        # NAT-purposed objects identified by description
        if nat_desc_refs:
            print(f"\n     OBJECTS WITH NAT IN DESCRIPTION"
                  f" (no inline NAT defined):")
            print(f"     These objects are referenced by NAT rules but")
            print(f"     have no inline Object NAT — likely used in")
            print(f"     Twice NAT rules above.")
            for obj in nat_desc_refs[:20]:
                val = obj['value'] or '(no value)'
                desc = obj['description'] or ''
                print(f"       {obj['name']:<30}"
                      f" {obj['type']:<10} {val:<20}"
                      f" [{desc[:30]}]")
            if len(nat_desc_refs) > 20:
                print(f"       ... and {len(nat_desc_refs) - 20} more")

    # ── Object-group inventory ────────────────────────────────
    print(f"\n  ── NETWORK OBJECT-GROUP INVENTORY"
          f" ({len(network_groups)} groups) " + "─" * 25)

    if not network_groups:
        print("     None detected.")
    else:
        nat_grp_refs = [g for g in network_groups.values()
                        if g['nat_desc_ref']]

        print(f"     Total groups             : {len(network_groups)}")
        print(f"     NAT-referenced by desc   : {len(nat_grp_refs)}")

        if nat_grp_refs:
            print(f"\n     OBJECT-GROUPS WITH NAT IN DESCRIPTION:")
            for grp in nat_grp_refs:
                member_count = len(grp['members'])
                desc = grp['description'] or ''
                print(f"       {grp['name']:<35}"
                      f" members: {member_count:<5}"
                      f" [{desc[:35]}]")

        print(f"\n     [MIGRATION NOTE] All network objects and")
        print(f"     object-groups must exist in FMC before NAT")
        print(f"     rules are deployed. FMT migrates objects")
        print(f"     automatically — verify post-migration.")
    print()


# ════════════════════════════════════════════════════════════
# PRINT: NAT GLOBAL SUMMARY
# ════════════════════════════════════════════════════════════

def print_nat_summary(twice_nat_rules, object_nat_rules,
                      network_objects, network_groups,
                      nat_partials, unmatched_nat):
    """Prints global NAT migration summary and risk assessment."""

    print(f"\n  {'='*78}")
    print(f"  NAT MIGRATION SUMMARY")
    print(f"  {'='*78}")

    total_nat = len(twice_nat_rules) + len(object_nat_rules)
    inactive  = [r for r in twice_nat_rules if r['inactive']]
    pat_iface = [r for r in object_nat_rules
                 if r['mapped'].lower() == 'interface']

    print(f"  Total NAT rules          : {total_nat}")
    print(f"  Twice NAT rules          : {len(twice_nat_rules)}")
    print(f"  Object NAT rules         : {len(object_nat_rules)}")
    print(f"  Network objects parsed   : {len(network_objects)}")
    print(f"  Network groups parsed    : {len(network_groups)}")
    print(f"  Inactive NAT rules       : {len(inactive)}")
    print(f"  Interface PAT rules      : {len(pat_iface)}")
    print(f"  Partial matches          : {len(nat_partials)}")

    print(f"\n  RISK ASSESSMENT")
    print(f"  " + "=" * 60)

    risks = []

    if inactive:
        risks.append(
            f"[HIGH] {len(inactive)} inactive Twice NAT rule(s) — "
            "must remove before FTD migration"
        )

    if twice_nat_rules:
        risks.append(
            f"[HIGH] {len(twice_nat_rules)} Twice NAT rule(s) require "
            "manual recreation in FMC — FMT does not migrate these"
        )

    if object_nat_rules:
        risks.append(
            f"[MEDIUM] {len(object_nat_rules)} Object NAT rule(s) — "
            "verify FMT migration output before cutover"
        )

    if pat_iface:
        risks.append(
            f"[MEDIUM] {len(pat_iface)} interface PAT rule(s) — "
            "verify correct interface selected in FMC post-migration"
        )

    if nat_partials:
        risks.append(
            f"[INFO] {len(nat_partials)} NAT line(s) partially matched "
            "— review manually, may represent unsupported syntax"
        )

    if not risks:
        print("  [OK] No NAT migration risks detected.")
    else:
        for r in risks:
            print(f"  * {r}")

    # ── Partial lines ─────────────────────────────────────────
    if nat_partials:
        print(f"\n  {'='*78}")
        print(f"  NAT PARTIAL MATCHES ({len(nat_partials)})")
        print(f"  {'='*78}")
        print("  These lines look like NAT statements but did not")
        print("  fully parse. Review manually:")
        for p in nat_partials[:20]:
            print(f"    {p[:75]}")
        if len(nat_partials) > 20:
            print(f"    ... and {len(nat_partials) - 20} more")

    # ── Unmatched NAT-context lines ───────────────────────────
    if unmatched_nat:
        print(f"\n  {'='*78}")
        print(f"  UNMATCHED NAT-CONTEXT LINES ({len(unmatched_nat)})")
        print(f"  {'='*78}")
        print("  These lines appeared in a NAT-related context but")
        print("  did not match any known pattern:")
        for u in unmatched_nat[:20]:
            print(f"    {u[:75]}")
        if len(unmatched_nat) > 20:
            print(f"    ... and {len(unmatched_nat) - 20} more")
    print()


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def print_header():
    print()
    print("=" * 78)
    print("  ASA MIGRATION PARSER — PHASE 5")
    print("  NAT Analysis: Twice NAT | Object NAT |")
    print("  Network Objects | Object-Groups")
    print("  Source: RUNNING-CONFIG-ALL (fallback: RUNNING-CONFIG)")
    print("=" * 78)
    print()


def main():
    if len(sys.argv) != 2:
        print("Usage: python asa_parser_p5.py <path_to_log_file>")
        print("Example: python asa_parser_p5.py asa_logs.txt")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.isfile(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    if os.path.getsize(filepath) == 0:
        print(f"[ERROR] File is empty: {filepath}")
        sys.exit(1)

    print_header()
    sections_data = extract_sections(filepath)

    # ── Source section selection ──────────────────────────────
    lines = sections_data.get("RUNNING-CONFIG-ALL", [])
    source = "RUNNING-CONFIG-ALL"

    if not lines:
        lines = sections_data.get("RUNNING-CONFIG", [])
        source = "RUNNING-CONFIG"

    if not lines:
        print("  [ERROR] Neither RUNNING-CONFIG-ALL nor RUNNING-CONFIG")
        print("  section found or both are empty.")
        print("  Verify your log file contains one of these sections.")
        sys.exit(1)

    print(f"  Reading NAT from section: {source}")
    print(f"  Total lines in section  : {len(lines)}\n")

    # ── Parse ─────────────────────────────────────────────────
    (
        twice_nat_rules,
        object_nat_rules,
        network_objects,
        network_groups,
        nat_partials,
        unmatched_nat,
    ) = parse_nat(lines)

    # ── Print sections ────────────────────────────────────────
    print("=" * 78)
    print("  NAT ANALYSIS")
    print("=" * 78)

    print_twice_nat(twice_nat_rules)
    print_object_nat(object_nat_rules, network_objects)
    print_network_objects(network_objects, network_groups)
    print_nat_summary(
        twice_nat_rules, object_nat_rules,
        network_objects, network_groups,
        nat_partials, unmatched_nat
    )


if __name__ == "__main__":
    main()
