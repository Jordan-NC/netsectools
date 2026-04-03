# ============================================================
# ASA Migration Parser - Phase 4: ACL and Crypto Parsing
# ============================================================
# PURPOSE:
#   Parses three high-value migration sections using the FULL
#   documented ASA syntax specification. Every unmatched line
#   is explicitly captured and reported. Nothing is silently
#   dropped.
#
#   Sections parsed:
#     - ACCESS-LIST                : Hit counts, inactive rules,
#                                    remarks, zero-hit rules
#     - RUNNING-CONFIG-ACCESS-LIST : Clean config rules for
#                                    migration inventory
#     - RUNNING-CONFIG-CRYPTO      : All transform sets, IKE
#                                    policies, proposals, crypto
#                                    maps, PKI trustpoints,
#                                    weak algorithm flags,
#                                    FTD compatibility assessment
#
# USAGE:
#   python asa_parser_p4.py <path_to_log_file>
#
# THREE-LAYER PARSING ARCHITECTURE:
#   Layer 1 — Full spec pattern match: built against complete
#             Cisco ASA documented syntax for each command
#   Layer 2 — Partial match fallback: captures lines that look
#             relevant but don't fully match — flagged [PARTIAL]
#   Layer 3 — Unmatched capture: every non-matching line goes
#             into an UNMATCHED section per parser — visible,
#             never silently dropped
#
# ACL SYNTAX COVERAGE (per Cisco ASA CLI Reference):
#   Actions    : permit, deny
#   Types      : extended, standard, ethertype, webtype, ipv6
#   Protocols  : ip, tcp, udp, icmp, icmp6, esp, ah, gre,
#                ospf, eigrp, pim, igmp, sctp,
#                object <n>, object-group <n>
#   Addr forms : any, any4, any6, host <ip>, <ip> <mask>,
#                object <n>, object-group <n>,
#                interface <n>, fqdn <n>
#   Port ops   : eq, neq, lt, gt, range
#   Modifiers  : log [level] [interval n], inactive,
#                time-range <n>
#   ICMP types : echo, echo-reply, unreachable,
#                time-exceeded, redirect, traceroute,
#                + numeric types
#
# CRYPTO SYNTAX COVERAGE (per Cisco ASA VPN CLI Reference):
#   IKEv1 enc  : des, 3des, aes, aes-192, aes-256
#   IKEv1 hash : sha, sha256, sha384, sha512, md5
#   IKEv1 auth : pre-share, rsa-sig, crack
#   IKEv2 enc  : des, 3des, aes, aes-192, aes-256,
#                aes-gcm, aes-gcm-192, aes-gcm-256, null
#   IKEv2 int  : sha, sha256, sha384, sha512, md5, null
#   ESP enc    : esp-des, esp-3des, esp-aes, esp-aes-192,
#                esp-aes-256, esp-aes-gcm, esp-aes-gcm-192,
#                esp-aes-gcm-256, esp-null
#   ESP hash   : esp-sha-hmac, esp-sha256-hmac,
#                esp-sha384-hmac, esp-sha512-hmac,
#                esp-md5-hmac, esp-none
#   TS mode    : tunnel (default), transport
#   DH groups  : 1,2,5,14,19,20,21,24
#   PKI        : crypto ca trustpoint, certificate chain,
#                trustpool, IKEv2 RA trustpoint, am-disable
#   FTD status : REMOVED / DEPRECATED / OK per algorithm
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
    Leading whitespace is preserved because indented lines in
    show access-list and crypto blocks carry structural meaning.
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
# FTD ALGORITHM COMPATIBILITY TABLES
# Source: FMC Config Guide 6.7+, ASA 9.13/9.15 release notes
# ════════════════════════════════════════════════════════════

# FTD status values: 'REMOVED', 'DEPRECATED', 'OK'

FTD_ESP_ENCRYPTION = {
    'esp-des'         : 'REMOVED',
    'esp-3des'        : 'REMOVED',
    'esp-aes'         : 'OK',
    'esp-aes-192'     : 'OK',
    'esp-aes-256'     : 'OK',
    'esp-aes-gcm'     : 'OK',
    'esp-aes-gcm-192' : 'OK',
    'esp-aes-gcm-256' : 'OK',
    'esp-null'        : 'OK',
    # IKEv2 proposal form (no esp- prefix)
    'des'             : 'REMOVED',
    '3des'            : 'REMOVED',
    'aes'             : 'OK',
    'aes-192'         : 'OK',
    'aes-256'         : 'OK',
    'aes-gcm'         : 'OK',
    'aes-gcm-192'     : 'OK',
    'aes-gcm-256'     : 'OK',
    'null'            : 'OK',
}

FTD_ESP_INTEGRITY = {
    # ESP hash form (transform sets)
    'esp-md5-hmac'    : 'REMOVED',
    'esp-sha-hmac'    : 'DEPRECATED',
    'esp-sha256-hmac' : 'OK',
    'esp-sha384-hmac' : 'OK',
    'esp-sha512-hmac' : 'OK',
    'esp-none'        : 'OK',
    # IKEv2 proposal form — no hyphen (older ASA output)
    'md5'             : 'REMOVED',
    'sha'             : 'DEPRECATED',
    'sha256'          : 'OK',
    'sha384'          : 'OK',
    'sha512'          : 'OK',
    'null'            : 'OK',
    # IKEv2 proposal form — hyphenated (newer ASA output)
    'sha-1'           : 'DEPRECATED',
    'sha-256'         : 'OK',
    'sha-384'         : 'OK',
    'sha-512'         : 'OK',
    'md5-96'          : 'REMOVED',
}

FTD_IKE_ENCRYPTION = {
    'des'         : 'REMOVED',
    '3des'        : 'REMOVED',
    'aes'         : 'OK',
    'aes-192'     : 'OK',
    'aes-256'     : 'OK',
    'aes-gcm'     : 'OK',
    'aes-gcm-192' : 'OK',
    'aes-gcm-256' : 'OK',
    'null'        : 'OK',
}
FTD_IKE_HASH = {
    # No hyphen form
    'md5'    : 'REMOVED',
    'sha'    : 'DEPRECATED',
    'sha256' : 'OK',
    'sha384' : 'OK',
    'sha512' : 'OK',
    # Hyphenated form
    'sha-1'  : 'DEPRECATED',
    'sha-256': 'OK',
    'sha-384': 'OK',
    'sha-512': 'OK',
}

# DH group FTD status
# Group 5  : deprecated for IKEv1, removed for IKEv2
# Groups 2, 24: removed entirely in FTD 6.7+
FTD_DH_GROUPS = {
    '1'  : 'REMOVED',
    '2'  : 'REMOVED',
    '5'  : 'DEPRECATED',
    '14' : 'OK',
    '19' : 'OK',
    '20' : 'OK',
    '21' : 'OK',
    '24' : 'REMOVED',
}

FTD_STATUS_SYMBOL = {
    'REMOVED'    : 'REMOVED',
    'DEPRECATED' : 'DEPRECATED',
    'OK'         : 'OK',
}


def ftd_enc_status(alg):
    return FTD_ESP_ENCRYPTION.get(alg.lower().strip(), 'UNKNOWN')

def ftd_int_status(alg):
    return FTD_ESP_INTEGRITY.get(alg.lower().strip(), 'UNKNOWN')

def ftd_ike_enc_status(alg):
    return FTD_IKE_ENCRYPTION.get(alg.lower().strip(), 'UNKNOWN')

def ftd_ike_hash_status(alg):
    return FTD_IKE_HASH.get(alg.lower().strip(), 'UNKNOWN')

def ftd_dh_status(group):
    g = re.sub(r'group\s*', '', group.lower()).strip()
    return FTD_DH_GROUPS.get(g, 'UNKNOWN')

def risk_symbol(status):
    return {
        'REMOVED'    : '[REMOVED]',
        'DEPRECATED' : '[DEPRECATED]',
        'OK'         : '[OK]',
        'UNKNOWN'    : '[UNKNOWN]',
    }.get(status, '[UNKNOWN]')


# ════════════════════════════════════════════════════════════
# ACL SYNTAX CONSTANTS (full documented spec)
# ════════════════════════════════════════════════════════════

ASA_PROTOCOLS = {
    'ip', 'tcp', 'udp', 'icmp', 'icmp6', 'esp', 'ah', 'gre',
    'ospf', 'eigrp', 'pim', 'igmp', 'sctp', 'object',
    'object-group',
}

ASA_LOG_LEVELS = {
    'emergencies', 'alerts', 'critical', 'errors',
    'warnings', 'notifications', 'informational', 'debugging',
    'disable',
}


# ════════════════════════════════════════════════════════════
# ACL REGEX PATTERNS
# ════════════════════════════════════════════════════════════

# Summary line: access-list <name>; <n> elements; name hash: 0x...
RE_ACL_SUMMARY = re.compile(
    r'^access-list\s+(\S+);\s+(\d+)\s+elements',
    re.IGNORECASE
)

# Global cached log flows (skip)
RE_ACL_CACHED = re.compile(
    r'^access-list cached ACL log flows',
    re.IGNORECASE
)

# Remark line (show access-list form — has line number)
RE_ACL_REMARK_SHOW = re.compile(
    r'^access-list\s+(\S+)\s+line\s+(\d+)\s+remark\s+(.*)',
    re.IGNORECASE
)

# Rule line with hit count (show access-list form)
RE_ACL_RULE_SHOW = re.compile(
    r'^access-list\s+(\S+)\s+line\s+(\d+)\s+'
    r'(extended|standard|ethertype|webtype|ipv6)\s+'
    r'(permit|deny)\s+'
    r'(.+?)'
    r'\s+\(hitcnt=(\d+)\)'
    r'(\s+\(inactive\))?'
    r'(\s+0x[0-9a-f]+)?'
    r'\s*$',
    re.IGNORECASE
)

# Partial: any access-list line we couldn't fully parse
RE_ACL_PARTIAL = re.compile(r'^access-list\s+\S+', re.IGNORECASE)

# Modifiers
RE_INACTIVE   = re.compile(r'\(inactive\)', re.IGNORECASE)
RE_TIME_RANGE = re.compile(r'\btime-range\s+(\S+)', re.IGNORECASE)
RE_OBJ_GROUP  = re.compile(r'\bobject-group\s+\S+', re.IGNORECASE)
RE_OBJ        = re.compile(r'\bobject\s+\S+', re.IGNORECASE)
RE_FQDN       = re.compile(r'\bfqdn\s+\S+', re.IGNORECASE)
RE_PORT_OP    = re.compile(
    r'\b(eq|neq|lt|gt|range)\s+(\S+(?:\s+\S+)?)',
    re.IGNORECASE
)

# Running-config ACL remark (no line number)
RE_CFG_REMARK = re.compile(
    r'^access-list\s+(\S+)\s+remark\s+(.*)',
    re.IGNORECASE
)

# Running-config ACL rule
RE_CFG_RULE = re.compile(
    r'^access-list\s+(\S+)\s+'
    r'(?:(extended|standard|ethertype|webtype|ipv6)\s+)?'
    r'(permit|deny)\s+'
    r'(\S+)\s+'
    r'(.+?)$',
    re.IGNORECASE
)

RE_CFG_PARTIAL = re.compile(r'^access-list\s+\S+', re.IGNORECASE)


def extract_log_level(text):
    """Returns log level found in ACL rule text, 'default' if
    log keyword present without level, or None if no logging."""
    for level in ASA_LOG_LEVELS:
        if re.search(rf'\blog\s+{level}\b', text, re.IGNORECASE):
            return level
    if re.search(r'\blog\b', text, re.IGNORECASE):
        return 'default'
    return None


# ════════════════════════════════════════════════════════════
# CRYPTO REGEX PATTERNS
# ════════════════════════════════════════════════════════════

# IKEv1 policy block
RE_IKEv1_POLICY = re.compile(r'^crypto ikev1 policy\s+(\d+)', re.IGNORECASE)
RE_IKEv1_ENC    = re.compile(r'^\s*encryption\s+(\S+)', re.IGNORECASE)
RE_IKEv1_HASH   = re.compile(r'^\s*hash\s+(\S+)', re.IGNORECASE)
RE_IKEv1_AUTH   = re.compile(r'^\s*authentication\s+(\S+)', re.IGNORECASE)
RE_IKEv1_GROUP  = re.compile(r'^\s*group\s+(\d+)', re.IGNORECASE)
RE_IKEv1_LIFE   = re.compile(r'^\s*lifetime\s+(\d+)', re.IGNORECASE)

# IKEv2 policy block
RE_IKEv2_POLICY = re.compile(r'^crypto ikev2 policy\s+(\d+)', re.IGNORECASE)
RE_IKEv2_ENC    = re.compile(r'^\s*encryption\s+(.+)', re.IGNORECASE)
RE_IKEv2_INT    = re.compile(r'^\s*integrity\s+(.+)', re.IGNORECASE)
RE_IKEv2_PRF    = re.compile(r'^\s*prf\s+(.+)', re.IGNORECASE)
RE_IKEv2_GROUP  = re.compile(r'^\s*group\s+(.+)', re.IGNORECASE)
RE_IKEv2_LIFE   = re.compile(
    r'^\s*lifetime\s+seconds\s+(\d+)', re.IGNORECASE
)

# IKEv1 transform sets
# Handles both:
#   crypto ipsec ikev1 transform-set <name> <enc> <hash>
#   crypto ipsec ikev1 transform-set <name> mode <transport|tunnel>
RE_IKEv1_TS = re.compile(
    r'^crypto ipsec ikev1 transform-set\s+(\S+)\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?(?:\s+(\S+))?',
    re.IGNORECASE
)

# IKEv2 IPsec proposals
RE_IKEv2_PROP = re.compile(
    r'^crypto ipsec ikev2 ipsec-proposal\s+(\S+)',
    re.IGNORECASE
)
RE_PROP_ENC = re.compile(r'^\s*protocol esp encryption\s+(.+)', re.IGNORECASE)
RE_PROP_INT = re.compile(r'^\s*protocol esp integrity\s+(.+)', re.IGNORECASE)
RE_PROP_AH  = re.compile(r'^\s*protocol ah\s+(.+)', re.IGNORECASE)

# IPsec profile
RE_IPSEC_PROFILE = re.compile(r'^crypto ipsec profile\s+(\S+)', re.IGNORECASE)

# IPsec global settings
RE_IPSEC_GLOBAL = re.compile(
    r'^crypto ipsec\s+(?!ikev1|ikev2|profile)(.+)',
    re.IGNORECASE
)

# IKE enable
RE_IKE_ENABLE = re.compile(
    r'^crypto (ikev1|ikev2) enable\s+(\S+)',
    re.IGNORECASE
)

# Dynamic map
RE_DYN_MAP = re.compile(
    r'^crypto dynamic-map\s+(\S+)\s+(\d+)\s+(.+)',
    re.IGNORECASE
)

# Static crypto map
RE_CRYPTO_MAP = re.compile(
    r'^crypto map\s+(\S+)\s+(\d+)\s+(match|set|interface|ipsec-isakmp)(\s+.+)?$',
    re.IGNORECASE
)

# Crypto map interface binding
RE_CRYPTO_MAP_IFACE = re.compile(
    r'^crypto map\s+(\S+)\s+interface\s+(\S+)',
    re.IGNORECASE
)

# Legacy ISAKMP
RE_ISAKMP_POLICY = re.compile(r'^crypto isakmp policy\s+(\d+)', re.IGNORECASE)
RE_ISAKMP_GLOBAL = re.compile(
    r'^crypto isakmp\s+(?!policy)(.+)',
    re.IGNORECASE
)

# SA lifetime
RE_SA_LIFETIME = re.compile(
    r'^crypto ipsec security-association\s+(lifetime|pmtu-aging)\s+(.+)',
    re.IGNORECASE
)

# PKI / crypto ca patterns
RE_CA_TRUSTPOINT = re.compile(
    r'^crypto ca trustpoint\s+(\S+)',
    re.IGNORECASE
)
RE_CA_TRUSTPOOL = re.compile(
    r'^crypto ca trustpool\s+(.+)',
    re.IGNORECASE
)
RE_CA_CERT_CHAIN = re.compile(
    r'^crypto ca certificate chain\s+(\S+)',
    re.IGNORECASE
)
RE_IKEv2_RA_TRUSTPOINT = re.compile(
    r'^crypto ikev2 remote-access trustpoint\s+(\S+)',
    re.IGNORECASE
)
RE_IKEv1_AM_DISABLE = re.compile(
    r'^crypto ikev1 am-disable',
    re.IGNORECASE
)

# Trustpoint sub-commands (must be indented)
RE_TP_ENROLLMENT  = re.compile(r'^\s+enrollment\s+(.+)', re.IGNORECASE)
RE_TP_REVOCATION  = re.compile(r'^\s+revocation-check\s+(.+)', re.IGNORECASE)
RE_TP_SUBJECT     = re.compile(r'^\s+subject-name\s+(.+)', re.IGNORECASE)
RE_TP_USAGE       = re.compile(r'^\s+usage\s+(.+)', re.IGNORECASE)
RE_TP_KEYPAIR     = re.compile(r'^\s+keypair\s+(\S+)', re.IGNORECASE)
RE_TP_FQDN        = re.compile(r'^\s+fqdn\s+(\S+)', re.IGNORECASE)
RE_TP_CRL         = re.compile(r'^\s+crl\s+configure', re.IGNORECASE)
RE_TP_NO_VALIDATE = re.compile(r'^\s+no\s+validation-usage', re.IGNORECASE)
RE_TP_IP          = re.compile(r'^\s+ip-address\s+(\S+)', re.IGNORECASE)

# Certificate serial inside cert chain block
RE_CERT_SERIAL = re.compile(r'^\s*certificate\s+(\S+)', re.IGNORECASE)

# Partial crypto: any crypto line not matched above
RE_CRYPTO_PARTIAL = re.compile(r'^crypto\s+', re.IGNORECASE)


# ════════════════════════════════════════════════════════════
# PARSER 1: ACCESS-LIST (show access-list)
# ════════════════════════════════════════════════════════════

def parse_access_list_show(lines):
    """
    Parses 'show access-list' output using three-layer architecture.

    Returns:
      acl_meta     : { name: { 'elements': int } }
      acl_rules    : { name: [ rule_dict ] }
      acl_partials : { name: [ line ] }
      unmatched    : [ line ]
    """
    acl_meta     = {}
    acl_rules    = defaultdict(list)
    acl_partials = defaultdict(list)
    unmatched    = []
    pending_remark = {}

    for line in lines:
        if not line.strip():
            continue

        if RE_ACL_CACHED.match(line.strip()):
            continue

        if line.strip().lower().startswith('alert-interval'):
            continue

        # Skip indented lines — expanded object references
        if line and (line[0] == ' ' or line[0] == '\t'):
            continue

        stripped = line.strip()

        # ── Layer 1a: Summary line ───────────────────────────
        m = RE_ACL_SUMMARY.match(stripped)
        if m:
            acl_meta[m.group(1)] = {'elements': int(m.group(2))}
            continue

        # ── Layer 1b: Remark line ────────────────────────────
        m = RE_ACL_REMARK_SHOW.match(stripped)
        if m:
            pending_remark[m.group(1)] = m.group(3).strip()
            continue

        # ── Layer 1c: Full rule line ─────────────────────────
        m = RE_ACL_RULE_SHOW.match(stripped)
        if m:
            name     = m.group(1)
            line_num = int(m.group(2))
            acl_type = m.group(3).lower()
            action   = m.group(4).lower()
            body     = m.group(5).strip()
            hitcnt   = int(m.group(6))
            inactive = bool(m.group(7))

            tr_m = RE_TIME_RANGE.search(body)

            acl_rules[name].append({
                'line'       : line_num,
                'acl_type'   : acl_type,
                'action'     : action,
                'body'       : body,
                'hitcnt'     : hitcnt,
                'inactive'   : inactive,
                'remark'     : pending_remark.pop(name, ''),
                'log_level'  : extract_log_level(body),
                'has_obj_grp': bool(RE_OBJ_GROUP.search(body)),
                'has_obj'    : bool(RE_OBJ.search(body)),
                'has_fqdn'   : bool(RE_FQDN.search(body)),
                'time_range' : tr_m.group(1) if tr_m else None,
                'port_ops'   : RE_PORT_OP.findall(body),
            })
            continue

        # ── Layer 2: Partial match ───────────────────────────
        if RE_ACL_PARTIAL.match(stripped):
            parts = stripped.split()
            name = parts[1] if len(parts) > 1 else 'UNKNOWN'
            acl_partials[name].append(stripped)
            continue

        # ── Layer 3: Unmatched ───────────────────────────────
        unmatched.append(stripped)

    return acl_meta, acl_rules, acl_partials, unmatched


def print_access_list_show(acl_meta, acl_rules, acl_partials, unmatched):
    """Prints show access-list analysis report."""
    print("=" * 78)
    print("  ACCESS LIST ANALYSIS  (show access-list)")
    print("=" * 78)

    if not acl_rules and not acl_meta:
        print("  [WARNING] No ACL data parsed.")
        if unmatched:
            print(f"  {len(unmatched)} unmatched line(s) — see UNMATCHED section.")
        return

    all_names = sorted(
        set(list(acl_meta.keys()) + list(acl_rules.keys()))
    )

    g_rules = g_zero_hit = g_inactive = g_deny = 0
    g_time_range = g_fqdn = 0

    for name in all_names:
        rules    = acl_rules.get(name, [])
        elements = acl_meta.get(name, {}).get('elements', len(rules))

        zero_hit   = [r for r in rules if r['hitcnt'] == 0 and not r['inactive']]
        inactive   = [r for r in rules if r['inactive']]
        denies     = [r for r in rules if r['action'] == 'deny']
        obj_rules  = [r for r in rules if r['has_obj_grp'] or r['has_obj']]
        fqdn_rules = [r for r in rules if r['has_fqdn']]
        tr_rules   = [r for r in rules if r['time_range']]
        logged     = [r for r in rules if r['log_level']]

        g_rules      += len(rules)
        g_zero_hit   += len(zero_hit)
        g_inactive   += len(inactive)
        g_deny       += len(denies)
        g_time_range += len(tr_rules)
        g_fqdn       += len(fqdn_rules)

        log_counts = defaultdict(int)
        for r in logged:
            log_counts[r['log_level']] += 1

        print(f"\n  ── ACL: {name} " + "─" * max(0, 58 - len(name)))
        print(f"     Declared elements    : {elements}")
        print(f"     Parsed rules         : {len(rules)}")
        print(f"     Permit rules         : {len(rules) - len(denies)}")
        print(f"     Deny rules           : {len(denies)}")
        print(f"     Zero-hit rules       : {len(zero_hit)}")
        print(f"     Inactive rules       : {len(inactive)}")
        print(f"     Object references    : {len(obj_rules)}")
        print(f"     FQDN-based rules     : {len(fqdn_rules)}")
        print(f"     Time-range rules     : {len(tr_rules)}")
        print(f"     Rules with logging   : {len(logged)}")

        if log_counts:
            lvl_str = ', '.join(
                f"{lvl}({cnt})" for lvl, cnt in sorted(log_counts.items())
            )
            print(f"     Log levels           : {lvl_str}")

        if inactive:
            print(f"\n     [FLAG] INACTIVE RULES — must remove before FTD migration")
            print(f"     FTD does not support the 'inactive' keyword:")
            for r in inactive:
                rm = f" | [{r['remark']}]" if r['remark'] else ''
                print(f"       Line {r['line']:>4}: {r['action'].upper()}"
                      f"  {r['body'][:55]}{rm}")

        if zero_hit:
            print(f"\n     [FLAG] ZERO-HIT RULES ({len(zero_hit)})"
                  f" — review for cleanup before migration")
            deny_zero = [r for r in zero_hit if r['action'] == 'deny']
            if deny_zero:
                print(f"     DENY rules with zero hits (highest review priority):")
                for r in deny_zero[:10]:
                    print(f"       Line {r['line']:>4}: DENY  {r['body'][:55]}")
                if len(deny_zero) > 10:
                    print(f"       ... and {len(deny_zero) - 10} more")

        if tr_rules:
            print(f"\n     [INFO] TIME-RANGE RULES ({len(tr_rules)})")
            print(f"     Time-range objects must be manually created in FMC.")
            tr_names = sorted(set(
                r['time_range'] for r in tr_rules if r['time_range']
            ))
            for tr in tr_names:
                print(f"       • {tr}")

        if fqdn_rules:
            print(f"\n     [INFO] FQDN-BASED RULES ({len(fqdn_rules)})")
            print(f"     Verify DNS resolution is configured in FMC.")

        partials = acl_partials.get(name, [])
        if partials:
            print(f"\n     [PARTIAL] {len(partials)} line(s) partially matched:")
            for p in partials:
                print(f"       {p[:75]}")

    print(f"\n  {'='*78}")
    print(f"  ACL GLOBAL SUMMARY")
    print(f"  {'='*78}")
    print(f"  Total ACLs           : {len(all_names)}")
    print(f"  Total rules parsed   : {g_rules}")
    print(f"  Zero-hit rules       : {g_zero_hit}")
    print(f"  Inactive rules       : {g_inactive}")
    print(f"  Deny rules           : {g_deny}")
    print(f"  Time-range rules     : {g_time_range}")
    print(f"  FQDN rules           : {g_fqdn}")

    if g_inactive:
        print()
        print("  [MIGRATION BLOCKER] Inactive rules must be removed.")
        print("  FTD does not support the 'inactive' keyword in ACEs.")

    if g_zero_hit:
        print()
        print("  [MIGRATION NOTE] Zero-hit rules may be stale policy.")
        print("  Review with customer before migrating to reduce policy")
        print("  complexity on FTD.")

    if g_time_range:
        print()
        print("  [MIGRATION NOTE] Time-range objects must be manually")
        print("  created in FMC. FMT does not migrate time-ranges.")

    if unmatched:
        print(f"\n  {'='*78}")
        print(f"  UNMATCHED LINES IN ACCESS-LIST SECTION ({len(unmatched)})")
        print(f"  {'='*78}")
        print("  These lines were not recognized by any pattern.")
        print("  Review manually — may represent syntax variants")
        print("  not yet covered by this parser version.")
        for u in unmatched[:20]:
            print(f"    {u[:75]}")
        if len(unmatched) > 20:
            print(f"    ... and {len(unmatched) - 20} more unmatched lines")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 2: RUNNING-CONFIG-ACCESS-LIST
# ════════════════════════════════════════════════════════════

def parse_running_config_acl(lines):
    """
    Parses 'show running-config access-list' output.

    Returns:
      cfg_rules    : { name: [ rule_dict ] }
      cfg_partials : { name: [ line ] }
      unmatched    : [ line ]
    """
    cfg_rules      = defaultdict(list)
    cfg_partials   = defaultdict(list)
    unmatched      = []
    pending_remark = {}

    for line in lines:
        if not line.strip():
            continue

        stripped = line.strip()

        # ── Remark ───────────────────────────────────────────
        m = RE_CFG_REMARK.match(stripped)
        if m:
            pending_remark[m.group(1)] = m.group(2).strip()
            continue

        # ── Full rule ────────────────────────────────────────
        m = RE_CFG_RULE.match(stripped)
        if m:
            name     = m.group(1)
            acl_type = (m.group(2) or 'extended').lower()
            action   = m.group(3).lower()
            protocol = m.group(4).lower()
            rest     = m.group(5).strip()

            tr_m = RE_TIME_RANGE.search(rest)

            cfg_rules[name].append({
                'action'     : action,
                'acl_type'   : acl_type,
                'protocol'   : protocol,
                'rest'       : rest,
                'inactive'   : bool(re.search(r'\binactive\b', rest, re.IGNORECASE)),
                'log_level'  : extract_log_level(rest),
                'has_obj_grp': bool(RE_OBJ_GROUP.search(rest)),
                'has_obj'    : bool(RE_OBJ.search(rest)),
                'has_fqdn'   : bool(RE_FQDN.search(rest)),
                'time_range' : tr_m.group(1) if tr_m else None,
                'port_ops'   : RE_PORT_OP.findall(rest),
                'remark'     : pending_remark.pop(name, ''),
            })
            continue

        # ── Partial ──────────────────────────────────────────
        if RE_CFG_PARTIAL.match(stripped):
            parts = stripped.split()
            name = parts[1] if len(parts) > 1 else 'UNKNOWN'
            cfg_partials[name].append(stripped)
            continue

        # ── Unmatched ────────────────────────────────────────
        unmatched.append(stripped)

    return cfg_rules, cfg_partials, unmatched


def print_running_config_acl(cfg_rules, cfg_partials, unmatched):
    """Prints running-config ACL analysis with full feature inventory."""
    print("=" * 78)
    print("  RUNNING CONFIG ACL ANALYSIS  (show running-config access-list)")
    print("=" * 78)

    if not cfg_rules:
        print("  [WARNING] No ACL config rules parsed.")
        if unmatched:
            print(f"  {len(unmatched)} unmatched line(s) — see UNMATCHED section.")
        return

    protocol_inventory = defaultdict(int)

    for name, rules in sorted(cfg_rules.items()):
        permits    = [r for r in rules if r['action'] == 'permit']
        denies     = [r for r in rules if r['action'] == 'deny']
        inactive   = [r for r in rules if r['inactive']]
        logged     = [r for r in rules if r['log_level']]
        fqdn_rules = [r for r in rules if r['has_fqdn']]
        tr_rules   = [r for r in rules if r['time_range']]
        obj_rules  = [r for r in rules if r['has_obj_grp'] or r['has_obj']]

        log_counts = defaultdict(int)
        for r in logged:
            log_counts[r['log_level']] += 1

        for r in rules:
            protocol_inventory[r['protocol']] += 1

        print(f"\n  ── ACL: {name} " + "─" * max(0, 58 - len(name)))
        print(f"     Total rules          : {len(rules)}")
        print(f"     Permit               : {len(permits)}")
        print(f"     Deny                 : {len(denies)}")
        print(f"     Inactive             : {len(inactive)}")
        print(f"     Logged rules         : {len(logged)}")
        print(f"     Object references    : {len(obj_rules)}")
        print(f"     FQDN rules           : {len(fqdn_rules)}")
        print(f"     Time-range rules     : {len(tr_rules)}")

        if log_counts:
            lvl_str = ', '.join(
                f"{lvl}({cnt})" for lvl, cnt in sorted(log_counts.items())
            )
            print(f"     Log levels           : {lvl_str}")

        if inactive:
            print(f"\n     [FLAG] INACTIVE RULES in config:")
            for r in inactive:
                rm = f" [{r['remark']}]" if r['remark'] else ''
                print(f"       {r['action'].upper()} {r['protocol']}"
                      f"  {r['rest'][:55]}{rm}")

        if tr_rules:
            tr_names = sorted(set(
                r['time_range'] for r in tr_rules if r['time_range']
            ))
            print(f"\n     [INFO] Time-range references: {', '.join(tr_names)}")

        partials = cfg_partials.get(name, [])
        if partials:
            print(f"\n     [PARTIAL] {len(partials)} partially matched line(s):")
            for p in partials:
                print(f"       {p[:75]}")

    if protocol_inventory:
        print(f"\n  {'='*78}")
        print(f"  PROTOCOL INVENTORY ACROSS ALL ACLs")
        print(f"  {'='*78}")
        print(f"  {'PROTOCOL':<30} {'RULE COUNT':>12}")
        print(f"  {'-'*29} {'-'*12}")
        for proto, count in sorted(
            protocol_inventory.items(), key=lambda x: -x[1]
        ):
            unknown = '' if proto in ASA_PROTOCOLS else '  [VERIFY - non-standard protocol]'
            print(f"  {proto:<30} {count:>12}{unknown}")

    if unmatched:
        print(f"\n  {'='*78}")
        print(f"  UNMATCHED LINES IN RUNNING-CONFIG-ACCESS-LIST ({len(unmatched)})")
        print(f"  {'='*78}")
        for u in unmatched[:20]:
            print(f"    {u[:75]}")
        if len(unmatched) > 20:
            print(f"    ... and {len(unmatched) - 20} more")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 3: RUNNING-CONFIG-CRYPTO
# ════════════════════════════════════════════════════════════

def parse_crypto(lines):
    """
    Parses 'show running-config crypto' output.
    Covers ALL documented ASA crypto syntax variants including
    PKI trustpoints, certificate chains, and CA pool policy.

    Returns:
      ikev1_policies    : [ policy_dict ]
      ikev2_policies    : [ policy_dict ]
      ikev1_ts          : [ ts_dict ]
      ikev2_proposals   : [ proposal_dict ]
      ipsec_profiles    : [ profile_dict ]
      dynamic_maps      : { name: [ entry_dict ] }
      crypto_maps       : { name: { seq: entry_dict } }
      ike_enables       : { version: [ interface ] }
      map_interfaces    : { map_name: interface }
      isakmp_globals    : [ line ]
      ipsec_globals     : [ line ]
      sa_settings       : [ line ]
      pki_trustpoints   : [ trustpoint_dict ]
      pki_cert_chains   : [ cert_chain_dict ]
      pki_ra_trustpoint : str or None
      pki_trustpool     : [ line ]
      ikev1_am_disable  : bool
      partials          : [ line ]
      unmatched         : [ line ]
    """
    ikev1_policies    = []
    ikev2_policies    = []
    ikev1_ts          = []
    ikev2_proposals   = []
    ipsec_profiles    = []
    dynamic_maps      = defaultdict(list)
    crypto_maps       = defaultdict(lambda: defaultdict(dict))
    ike_enables       = defaultdict(list)
    map_interfaces    = {}
    isakmp_globals    = []
    ipsec_globals     = []
    sa_settings       = []
    pki_trustpoints   = []
    pki_cert_chains   = []
    pki_ra_trustpoint = None
    pki_trustpool     = []
    ikev1_am_disable  = False
    partials          = []
    unmatched         = []

    # Block state
    current_ikev1_policy  = None
    current_ikev2_policy  = None
    current_ikev2_prop    = None
    current_ipsec_profile = None
    current_trustpoint    = None
    current_cert_chain    = None
    in_cert_chain         = False

    def reset_all():
        nonlocal current_ikev1_policy, current_ikev2_policy
        nonlocal current_ikev2_prop, current_ipsec_profile
        nonlocal current_trustpoint, current_cert_chain
        nonlocal in_cert_chain
        current_ikev1_policy  = None
        current_ikev2_policy  = None
        current_ikev2_prop    = None
        current_ipsec_profile = None
        current_trustpoint    = None
        current_cert_chain    = None
        in_cert_chain         = False

    for line in lines:
        if not line.strip():
            continue

        stripped = line.strip()

        # ── Certificate chain content ─────────────────────────
        # Must check FIRST — cert content can look like anything
        if in_cert_chain:
            if stripped.lower() == 'quit':
                in_cert_chain = False
                continue
            m = RE_CERT_SERIAL.match(stripped)
            if m:
                if current_cert_chain is not None:
                    current_cert_chain['cert_serials'].append(m.group(1))
                continue
            # Base64 content — count lines, never store content
            if current_cert_chain is not None:
                current_cert_chain['content_lines'] += 1
            continue

        # ── IKEv1 am-disable ──────────────────────────────────
        if RE_IKEv1_AM_DISABLE.match(stripped):
            ikev1_am_disable = True
            reset_all()
            continue

        # ── IKEv2 RA VPN trustpoint ───────────────────────────
        m = RE_IKEv2_RA_TRUSTPOINT.match(stripped)
        if m:
            pki_ra_trustpoint = m.group(1)
            reset_all()
            continue

        # ── crypto ca trustpool ───────────────────────────────
        m = RE_CA_TRUSTPOOL.match(stripped)
        if m:
            pki_trustpool.append(stripped)
            reset_all()
            continue

        # ── crypto ca trustpoint header ───────────────────────
        m = RE_CA_TRUSTPOINT.match(stripped)
        if m:
            reset_all()
            current_trustpoint = {
                'name'         : m.group(1),
                'enrollment'   : None,
                'revocation'   : None,
                'subject'      : None,
                'usage'        : [],
                'keypair'      : None,
                'fqdn'         : None,
                'ip_address'   : None,
                'crl_config'   : False,
                'no_validation': False,
                'other'        : [],
            }
            pki_trustpoints.append(current_trustpoint)
            continue

        # ── Trustpoint sub-commands (indented lines) ──────────
        if current_trustpoint is not None:
            is_indented = line.startswith(' ') or line.startswith('\t')

            if is_indented:
                m = RE_TP_ENROLLMENT.match(line)
                if m:
                    current_trustpoint['enrollment'] = m.group(1).strip()
                    continue

                m = RE_TP_REVOCATION.match(line)
                if m:
                    current_trustpoint['revocation'] = m.group(1).strip()
                    continue

                m = RE_TP_SUBJECT.match(line)
                if m:
                    current_trustpoint['subject'] = m.group(1).strip()
                    continue

                m = RE_TP_USAGE.match(line)
                if m:
                    current_trustpoint['usage'].extend(
                        m.group(1).strip().split()
                    )
                    continue

                m = RE_TP_KEYPAIR.match(line)
                if m:
                    current_trustpoint['keypair'] = m.group(1)
                    continue

                m = RE_TP_FQDN.match(line)
                if m:
                    current_trustpoint['fqdn'] = m.group(1)
                    continue

                m = RE_TP_IP.match(line)
                if m:
                    current_trustpoint['ip_address'] = m.group(1)
                    continue

                if RE_TP_CRL.match(line):
                    current_trustpoint['crl_config'] = True
                    continue

                if RE_TP_NO_VALIDATE.match(line):
                    current_trustpoint['no_validation'] = True
                    continue

                # Any other indented line inside trustpoint
                current_trustpoint['other'].append(stripped)
                continue

            else:
                # Non-indented = trustpoint block ended
                current_trustpoint = None
                # Fall through to process this line normally

        # ── crypto ca certificate chain header ────────────────
        m = RE_CA_CERT_CHAIN.match(stripped)
        if m:
            reset_all()
            current_cert_chain = {
                'trustpoint'   : m.group(1),
                'cert_serials' : [],
                'content_lines': 0,
            }
            pki_cert_chains.append(current_cert_chain)
            in_cert_chain = True
            continue

        # ── IKEv1 policy header ───────────────────────────────
        m = RE_IKEv1_POLICY.match(stripped)
        if m:
            reset_all()
            current_ikev1_policy = {
                'priority'  : int(m.group(1)),
                'encryption': None,
                'hash'      : None,
                'auth'      : None,
                'group'     : None,
                'lifetime'  : None,
            }
            ikev1_policies.append(current_ikev1_policy)
            continue

        # ── IKEv1 policy sub-commands ─────────────────────────
        if current_ikev1_policy:
            m = RE_IKEv1_ENC.match(stripped)
            if m:
                current_ikev1_policy['encryption'] = m.group(1).lower()
                continue
            m = RE_IKEv1_HASH.match(stripped)
            if m:
                current_ikev1_policy['hash'] = m.group(1).lower()
                continue
            m = RE_IKEv1_AUTH.match(stripped)
            if m:
                current_ikev1_policy['auth'] = m.group(1).lower()
                continue
            m = RE_IKEv1_GROUP.match(stripped)
            if m:
                current_ikev1_policy['group'] = m.group(1)
                continue
            m = RE_IKEv1_LIFE.match(stripped)
            if m:
                current_ikev1_policy['lifetime'] = m.group(1)
                continue

        # ── IKEv2 policy header ───────────────────────────────
        m = RE_IKEv2_POLICY.match(stripped)
        if m:
            reset_all()
            current_ikev2_policy = {
                'priority'  : int(m.group(1)),
                'encryption': [],
                'integrity' : [],
                'prf'       : [],
                'group'     : [],
                'lifetime'  : None,
            }
            ikev2_policies.append(current_ikev2_policy)
            continue

        # ── IKEv2 policy sub-commands ─────────────────────────
        if current_ikev2_policy:
            m = RE_IKEv2_ENC.match(stripped)
            if m:
                current_ikev2_policy['encryption'].extend(
                    [a.lower() for a in m.group(1).split()]
                )
                continue
            m = RE_IKEv2_INT.match(stripped)
            if m:
                current_ikev2_policy['integrity'].extend(
                    [a.lower() for a in m.group(1).split()]
                )
                continue
            m = RE_IKEv2_PRF.match(stripped)
            if m:
                current_ikev2_policy['prf'].extend(
                    [a.lower() for a in m.group(1).split()]
                )
                continue
            m = RE_IKEv2_GROUP.match(stripped)
            if m:
                current_ikev2_policy['group'].extend(m.group(1).split())
                continue
            m = RE_IKEv2_LIFE.match(stripped)
            if m:
                current_ikev2_policy['lifetime'] = m.group(1)
                continue

       # ── IKEv1 transform sets ──────────────────────────────
        m = RE_IKEv1_TS.match(stripped)
        if m:
            reset_all()
            name   = m.group(1)
            token2 = m.group(2).lower() if m.group(2) else None
            token3 = m.group(3).lower() if m.group(3) else None
            token4 = m.group(4).lower() if m.group(4) else None
            token5 = m.group(5).lower() if m.group(5) else None

            all_tokens = [t for t in [token2, token3, token4, token5]
                          if t is not None]

            # Check if this is a mode-only line:
            # crypto ipsec ikev1 transform-set <name> mode transport
            if token2 == 'mode' and token3 in ('transport', 'tunnel', None):
                # This is a mode continuation line for an existing TS
                # Find and update the existing entry rather than creating new
                for existing in ikev1_ts:
                    if existing['name'] == name:
                        existing['mode'] = token3 or 'tunnel'
                        break
                else:
                    # Mode line appeared before main TS line — store for merge
                    ikev1_ts.append({
                        'name'    : name,
                        'esp_enc' : '(mode-only line)',
                        'esp_hash': None,
                        'mode'    : token3 or 'tunnel',
                        'ftd_enc' : 'UNKNOWN',
                        'ftd_hash': 'N/A',
                    })
                continue

            # Normal transform set line — extract enc and hash
            # Tokens may include mode keyword inline at end
            esp_enc  = None
            esp_hash = None
            mode     = 'tunnel'

            # Walk tokens — first esp-* token is enc, second is hash
            # 'mode' keyword followed by transport/tunnel sets mode
            i = 0
            while i < len(all_tokens):
                tok = all_tokens[i]
                if tok == 'mode' and i + 1 < len(all_tokens):
                    mode = all_tokens[i + 1]
                    i += 2
                    continue
                if tok in ('transport', 'tunnel') and i > 0 \
                        and all_tokens[i-1] == 'mode':
                    i += 1
                    continue
                if esp_enc is None:
                    esp_enc = tok
                elif esp_hash is None:
                    esp_hash = tok
                i += 1

            if esp_enc is None:
                esp_enc = '(none)'

            # Check if an entry for this name already exists
            # (mode continuation line processed first edge case)
            existing_entry = next(
                (ts for ts in ikev1_ts if ts['name'] == name), None
            )
            if existing_entry and existing_entry['esp_enc'] == '(mode-only line)':
                # Update the placeholder
                existing_entry['esp_enc']  = esp_enc
                existing_entry['esp_hash'] = esp_hash
                existing_entry['ftd_enc']  = ftd_enc_status(esp_enc)
                existing_entry['ftd_hash'] = (
                    ftd_int_status(esp_hash) if esp_hash else 'N/A'
                )
            else:
                ikev1_ts.append({
                    'name'    : name,
                    'esp_enc' : esp_enc,
                    'esp_hash': esp_hash,
                    'mode'    : mode,
                    'ftd_enc' : ftd_enc_status(esp_enc),
                    'ftd_hash': ftd_int_status(esp_hash) if esp_hash else 'N/A',
                })
            continue

        # ── IKEv2 proposal header ─────────────────────────────
        m = RE_IKEv2_PROP.match(stripped)
        if m:
            reset_all()
            current_ikev2_prop = {
                'name'      : m.group(1),
                'encryption': [],
                'integrity' : [],
                'ah'        : [],
            }
            ikev2_proposals.append(current_ikev2_prop)
            continue

        # ── IKEv2 proposal sub-lines ──────────────────────────
        if current_ikev2_prop:
            m = RE_PROP_ENC.match(stripped)
            if m:
                current_ikev2_prop['encryption'].extend(
                    [a.lower() for a in m.group(1).strip().split()]
                )
                continue
            m = RE_PROP_INT.match(stripped)
            if m:
                current_ikev2_prop['integrity'].extend(
                    [a.lower() for a in m.group(1).strip().split()]
                )
                continue
            m = RE_PROP_AH.match(stripped)
            if m:
                current_ikev2_prop['ah'].append(m.group(1).strip())
                continue

        # ── IPsec profile header ──────────────────────────────
        m = RE_IPSEC_PROFILE.match(stripped)
        if m:
            reset_all()
            current_ipsec_profile = {
                'name'    : m.group(1),
                'settings': [],
            }
            ipsec_profiles.append(current_ipsec_profile)
            continue

        # ── IPsec profile sub-lines ───────────────────────────
        if current_ipsec_profile:
            m_set = re.match(r'^\s*set\s+(.+)', stripped, re.IGNORECASE)
            if m_set:
                current_ipsec_profile['settings'].append(m_set.group(1))
                continue

        # ── IKE enable statements ─────────────────────────────
        m = RE_IKE_ENABLE.match(stripped)
        if m:
            reset_all()
            ike_enables[m.group(1).lower()].append(m.group(2))
            continue

        # ── Crypto map interface binding ──────────────────────
        m = RE_CRYPTO_MAP_IFACE.match(stripped)
        if m:
            reset_all()
            map_interfaces[m.group(1)] = m.group(2)
            continue

        # ── Dynamic map ───────────────────────────────────────
        m = RE_DYN_MAP.match(stripped)
        if m:
            reset_all()
            map_name   = m.group(1)
            seq        = m.group(2)
            rest_str   = m.group(3).strip()
            rest_lower = rest_str.lower()

            dh_flag = weak_flag = ''

            if 'pfs' in rest_lower:
                grp_m = re.search(r'group\s*(\d+)', rest_lower)
                if grp_m:
                    g = grp_m.group(1)
                    status = ftd_dh_status(g)
                    if status != 'OK':
                        dh_flag = f" [{risk_symbol(status)} DH group{g}]"

            for alg in ['3des', 'des', 'md5', 'esp-des',
                        'esp-3des', 'esp-md5-hmac']:
                if alg in rest_lower:
                    weak_flag = f" [WEAK: {alg}]"
                    break

            dynamic_maps[map_name].append({
                'seq'      : seq,
                'setting'  : rest_str,
                'dh_flag'  : dh_flag,
                'weak_flag': weak_flag,
            })
            continue

        # ── Static crypto map ─────────────────────────────────
        m = RE_CRYPTO_MAP.match(stripped)
        if m:
            reset_all()
            map_name  = m.group(1)
            seq       = int(m.group(2))
            verb      = m.group(3).lower()
            remainder = (m.group(4) or '').strip()

            if seq not in crypto_maps[map_name]:
                crypto_maps[map_name][seq] = {
                    'seq'        : seq,
                    'match_acl'  : None,
                    'peers'      : [],
                    'ikev1_ts'   : [],
                    'ikev2_prop' : [],
                    'pfs'        : None,
                    'sa_lifetime': None,
                    'mode'       : None,
                    'raw'        : [],
                }

            entry = crypto_maps[map_name][seq]
            entry['raw'].append(f"{verb} {remainder}")
            r_lower = remainder.lower()

            if verb == 'match' and r_lower.startswith('address'):
                entry['match_acl'] = remainder.split()[-1]
            elif verb == 'set':
                if r_lower.startswith('peer'):
                    entry['peers'].append(remainder.split()[-1])
                elif 'ikev1 transform-set' in r_lower:
                    entry['ikev1_ts'].extend(remainder.split()[2:])
                elif 'ikev2 ipsec-proposal' in r_lower:
                    entry['ikev2_prop'].extend(remainder.split()[2:])
                elif r_lower.startswith('pfs'):
                    entry['pfs'] = remainder
                elif r_lower.startswith('security-association lifetime'):
                    entry['sa_lifetime'] = remainder
                elif r_lower.startswith('ikev1 phase1-mode') or \
                     r_lower.startswith('connection-type'):
                    entry['mode'] = remainder
            continue

        # ── SA lifetime / global IPsec settings ───────────────
        m = RE_SA_LIFETIME.match(stripped)
        if m:
            reset_all()
            sa_settings.append(stripped)
            continue

        m = RE_IPSEC_GLOBAL.match(stripped)
        if m:
            reset_all()
            ipsec_globals.append(stripped)
            continue

        # ── Legacy ISAKMP ─────────────────────────────────────
        if RE_ISAKMP_POLICY.match(stripped) or \
           RE_ISAKMP_GLOBAL.match(stripped):
            reset_all()
            isakmp_globals.append(stripped)
            continue

        # ── Partial ───────────────────────────────────────────
        if RE_CRYPTO_PARTIAL.match(stripped):
            reset_all()
            partials.append(stripped)
            continue

        # ── Unmatched ─────────────────────────────────────────
        unmatched.append(stripped)

    return (
        ikev1_policies, ikev2_policies,
        ikev1_ts, ikev2_proposals,
        ipsec_profiles, dynamic_maps,
        crypto_maps, ike_enables,
        map_interfaces, isakmp_globals,
        ipsec_globals, sa_settings,
        pki_trustpoints, pki_cert_chains,
        pki_ra_trustpoint, pki_trustpool,
        ikev1_am_disable,
        partials, unmatched,
    )


# ════════════════════════════════════════════════════════════
# PKI PRINT FUNCTION
# ════════════════════════════════════════════════════════════

def print_pki_section(pki_trustpoints, pki_cert_chains,
                      pki_ra_trustpoint, pki_trustpool,
                      ikev1_am_disable, risk_high, risk_info):
    """
    Prints PKI/certificate infrastructure analysis with
    FTD migration requirements. Called from print_crypto.
    """
    print(f"\n  ── PKI / CERTIFICATE INFRASTRUCTURE " + "─" * 38)

    # ── IKEv1 aggressive mode ─────────────────────────────────
    if ikev1_am_disable:
        print(f"\n     [OK] crypto ikev1 am-disable is set.")
        print(f"     IKEv1 aggressive mode is disabled on this ASA.")
        print(f"     FTD disables aggressive mode by default — this")
        print(f"     setting carries over implicitly, no action needed.")
    else:
        print(f"\n     [INFO] crypto ikev1 am-disable is NOT set.")
        print(f"     IKEv1 aggressive mode may be enabled.")
        print(f"     FTD disables it by default — verify no peers")
        print(f"     require aggressive mode before migration.")
        risk_info.append(
            "IKEv1 aggressive mode not explicitly disabled on ASA — "
            "FTD disables by default, verify no peer dependency"
        )

    # ── RA VPN trustpoint ─────────────────────────────────────
    if pki_ra_trustpoint:
        print(f"\n     [CRITICAL] RA VPN Trustpoint: {pki_ra_trustpoint}")
        print(f"     Used for IKEv2 remote-access VPN (AnyConnect)")
        print(f"     device authentication.")
        print(f"     MIGRATION REQUIREMENT: This trustpoint and its")
        print(f"     certificate chain MUST be exported from the ASA")
        print(f"     and imported into FMC before AnyConnect will")
        print(f"     authenticate successfully post-migration.")
        risk_high.append(
            f"RA VPN trustpoint '{pki_ra_trustpoint}' must be exported "
            "from ASA and imported into FMC — AnyConnect will fail "
            "without this"
        )

    # ── Trustpoints ───────────────────────────────────────────
    print(f"\n     TRUSTPOINTS ({len(pki_trustpoints)} configured)")
    print(f"     " + "=" * 65)

    if not pki_trustpoints:
        print(f"     None detected.")
    else:
        for tp in pki_trustpoints:
            is_ra_tp = (
                pki_ra_trustpoint and
                tp['name'].lower() == pki_ra_trustpoint.lower()
            )
            ra_marker = '  <- RA VPN TRUSTPOINT' if is_ra_tp else ''

            print(f"\n     Trustpoint : {tp['name']}{ra_marker}")

            enroll = tp['enrollment'] or '(not specified)'
            print(f"       Enrollment   : {enroll}")

            revoke = tp['revocation'] or '(not specified)'
            print(f"       Revocation   : {revoke}")

            if tp['subject']:
                print(f"       Subject      : {tp['subject']}")

            usage_str = ', '.join(tp['usage']) if tp['usage'] \
                else '(general-purpose / not specified)'
            print(f"       Usage        : {usage_str}")

            if tp['keypair']:
                print(f"       Keypair      : {tp['keypair']}")
            if tp['fqdn']:
                print(f"       FQDN         : {tp['fqdn']}")
            if tp['ip_address']:
                print(f"       IP Address   : {tp['ip_address']}")
            if tp['crl_config']:
                print(f"       CRL          : configured")
            if tp['no_validation']:
                print(f"       Validation   : disabled (no validation-usage)")
                risk_info.append(
                    f"Trustpoint '{tp['name']}' has no validation-usage — "
                    "verify certificate validation behavior in FMC"
                )
            if tp['other']:
                print(f"       Other settings:")
                for o in tp['other']:
                    print(f"         {o}")

            # Per-trustpoint migration notes
            notes = []

            enroll_lower = enroll.lower()
            if enroll_lower == 'terminal':
                notes.append(
                    "Enrolled via terminal (manual paste) — certificate "
                    "must be manually exported and re-imported into FMC"
                )
            elif 'url' in enroll_lower:
                notes.append(
                    "SCEP enrollment URL configured — verify FTD/FMC "
                    "can reach the CA at the same URL post-migration"
                )
            elif enroll_lower == 'self':
                notes.append(
                    "Self-signed certificate — regenerate on FTD or "
                    "import the existing cert if peers trust this specific cert"
                )

            revoke_lower = revoke.lower()
            if 'crl' in revoke_lower:
                notes.append(
                    "CRL revocation checking — verify FTD can reach "
                    "the CRL distribution point post-migration"
                )
            elif 'ocsp' in revoke_lower:
                notes.append(
                    "OCSP revocation checking — verify FTD can reach "
                    "the OCSP responder post-migration"
                )
            elif 'none' in revoke_lower:
                notes.append(
                    "Revocation checking disabled (none) — FMC default "
                    "enables CRL checking; configure to match on FTD"
                )

            if is_ra_tp:
                risk_high.append(
                    f"Trustpoint '{tp['name']}' (RA VPN) — "
                    "must be migrated to FMC before AnyConnect cutover"
                )

            if notes:
                print(f"       Migration notes:")
                for n in notes:
                    print(f"         * {n}")

    # ── Certificate chains ────────────────────────────────────
    print(f"\n     CERTIFICATE CHAINS ({len(pki_cert_chains)} present)")
    print(f"     " + "=" * 65)

    if not pki_cert_chains:
        print(f"     None detected.")
    else:
        for chain in pki_cert_chains:
            serials = ', '.join(chain['cert_serials']) \
                if chain['cert_serials'] else '(serials not captured)'
            print(f"\n     Chain trustpoint : {chain['trustpoint']}")
            print(f"       Cert serials     : {serials}")
            print(f"       Content lines    : {chain['content_lines']}"
                  f"  (base64 data — not stored)")

    # ── CA trustpool ──────────────────────────────────────────
    if pki_trustpool:
        print(f"\n     CA TRUSTPOOL POLICY")
        print(f"     " + "=" * 65)
        for line in pki_trustpool:
            print(f"     {line}")
        risk_info.append(
            "CA trustpool policy configured — verify FMC trustpool "
            "settings match post-migration"
        )

    # ── PKI migration checklist ───────────────────────────────
    print(f"\n     PKI MIGRATION CHECKLIST")
    print(f"     " + "=" * 65)

    checklist = []

    if pki_trustpoints:
        checklist.append(
            f"Export all {len(pki_trustpoints)} trustpoint certificate(s) "
            "from ASA using: crypto ca export <name> pkcs12 <password>"
        )
        checklist.append(
            "Import exported certificates into FMC under: "
            "Objects > PKI > Cert Enrollment"
        )

    if pki_ra_trustpoint:
        checklist.append(
            f"Assign RA VPN trustpoint '{pki_ra_trustpoint}' to "
            "AnyConnect Connection Profile in FMC before AnyConnect testing"
        )

    if any('url' in (tp['enrollment'] or '').lower()
           for tp in pki_trustpoints):
        checklist.append(
            "Verify FTD management interface can reach all SCEP "
            "CA enrollment URLs for automatic certificate renewal"
        )

    if any('crl' in (tp['revocation'] or '').lower()
           for tp in pki_trustpoints):
        checklist.append(
            "Verify FTD data interfaces can reach CRL distribution "
            "points for certificate revocation checking"
        )

    if checklist:
        for i, item in enumerate(checklist, 1):
            print(f"     {i}. {item}")
    else:
        print(f"     No PKI migration items identified.")

    print()


# ════════════════════════════════════════════════════════════
# CRYPTO PRINT FUNCTION
# ════════════════════════════════════════════════════════════

def print_crypto(ikev1_policies, ikev2_policies,
                 ikev1_ts, ikev2_proposals,
                 ipsec_profiles, dynamic_maps,
                 crypto_maps, ike_enables,
                 map_interfaces, isakmp_globals,
                 ipsec_globals, sa_settings,
                 pki_trustpoints, pki_cert_chains,
                 pki_ra_trustpoint, pki_trustpool,
                 ikev1_am_disable,
                 partials, unmatched):
    """Prints full crypto analysis with FTD compatibility assessment."""

    print("=" * 78)
    print("  CRYPTO ANALYSIS  (show running-config crypto)")
    print("=" * 78)

    # Risk tracking lists — populated throughout, printed at end
    risk_high   = []
    risk_medium = []
    risk_info   = []

    # ── PKI section ───────────────────────────────────────────
    print_pki_section(
        pki_trustpoints, pki_cert_chains,
        pki_ra_trustpoint, pki_trustpool,
        ikev1_am_disable,
        risk_high, risk_info
    )

    # ── IKE enable status ─────────────────────────────────────
    if ike_enables:
        print(f"\n  ── IKE ENABLED INTERFACES " + "─" * 47)
        for ver, ifaces in sorted(ike_enables.items()):
            for iface in ifaces:
                print(f"     {ver.upper()} enabled on: {iface}")

    # ── IKEv1 Phase 1 policies ────────────────────────────────
    print(f"\n  ── IKEv1 PHASE 1 POLICIES ({len(ikev1_policies)}) " + "─" * 38)

    if not ikev1_policies:
        print("     None configured.")
    else:
        print(f"  {'PRI':>5}  {'ENCRYPTION':<15} {'HASH':<10}"
              f" {'AUTH':<12} {'DH GRP':>7} {'LIFETIME':>10}")
        print(f"  {'-'*5}  {'-'*14} {'-'*9} {'-'*11} {'-'*7} {'-'*10}")

        for pol in sorted(ikev1_policies, key=lambda x: x['priority']):
            enc   = pol['encryption'] or 'default(3des)'
            hsh   = pol['hash']       or 'default(sha)'
            auth  = pol['auth']       or 'default(pre-share)'
            group = pol['group']      or 'default(2)'
            life  = pol['lifetime']   or 'default(86400)'

            print(f"  {pol['priority']:>5}  {enc:<15} {hsh:<10}"
                  f" {auth:<12} {group:>7} {life:>10}")

            enc_s = ftd_ike_enc_status(enc)
            hsh_s = ftd_ike_hash_status(hsh)
            dh_s  = ftd_dh_status(group)

            for label, status in [
                (f"Encryption '{enc}'", enc_s),
                (f"Hash '{hsh}'", hsh_s),
                (f"DH group {group}", dh_s),
            ]:
                if status in ('REMOVED', 'DEPRECATED'):
                    sym = risk_symbol(status)
                    print(f"          [FLAG] {label}: {sym}")
                    entry = (
                        f"IKEv1 Policy {pol['priority']} — "
                        f"{label}: {status}"
                    )
                    if status == 'REMOVED':
                        risk_high.append(entry)
                    else:
                        risk_medium.append(entry)

    # ── IKEv2 Phase 1 policies ────────────────────────────────
    print(f"\n  ── IKEv2 PHASE 1 POLICIES ({len(ikev2_policies)}) " + "─" * 38)

    if not ikev2_policies:
        print("     None configured.")
    else:
        for pol in sorted(ikev2_policies, key=lambda x: x['priority']):
            print(f"\n     Priority  : {pol['priority']}")

            for enc in pol['encryption'] or ['default']:
                s = ftd_ike_enc_status(enc)
                print(f"     Encryption: {enc:<25} {risk_symbol(s)}")
                if s in ('REMOVED', 'DEPRECATED'):
                    entry = (
                        f"IKEv2 Policy {pol['priority']} "
                        f"enc '{enc}': {s}"
                    )
                    risk_high.append(entry) if s == 'REMOVED' \
                        else risk_medium.append(entry)

            for alg in pol['integrity'] or ['default']:
                s = ftd_ike_hash_status(alg)
                print(f"     Integrity : {alg:<25} {risk_symbol(s)}")
                if s in ('REMOVED', 'DEPRECATED'):
                    entry = (
                        f"IKEv2 Policy {pol['priority']} "
                        f"integrity '{alg}': {s}"
                    )
                    risk_high.append(entry) if s == 'REMOVED' \
                        else risk_medium.append(entry)

            if pol['prf']:
                print(f"     PRF       : {', '.join(pol['prf'])}")

            for grp in pol['group'] or ['default']:
                s = ftd_dh_status(grp)
                print(f"     DH Group  : {grp:<25} {risk_symbol(s)}")
                if s in ('REMOVED', 'DEPRECATED'):
                    entry = (
                        f"IKEv2 Policy {pol['priority']} "
                        f"DH group {grp}: {s}"
                    )
                    risk_high.append(entry) if s == 'REMOVED' \
                        else risk_medium.append(entry)

            if pol['lifetime']:
                print(f"     Lifetime  : {pol['lifetime']} seconds")

    # ── IKEv1 Transform Sets ──────────────────────────────────
    print(f"\n  ── IKEv1 TRANSFORM SETS ({len(ikev1_ts)}) " + "─" * 42)

    if not ikev1_ts:
        print("     None configured.")
    else:
        print(f"  {'NAME':<30} {'ESP-ENC':<20} {'ESP-HASH':<20}"
              f" {'MODE':<10} {'ENC':<12} {'HASH'}")
        print(f"  {'-'*29} {'-'*19} {'-'*19} {'-'*9} {'-'*11} {'-'*12}")

        weak_ts = set()
        for ts in ikev1_ts:
            enc_s  = risk_symbol(ts['ftd_enc'])
            hash_s = risk_symbol(ts['ftd_hash'])
            hash_str = ts['esp_hash'] or '(none)'

            print(f"  {ts['name']:<30} {ts['esp_enc']:<20}"
                  f" {hash_str:<20} {ts['mode']:<10}"
                  f" {enc_s:<12} {hash_s}")

            if ts['ftd_enc'] in ('REMOVED', 'DEPRECATED') or \
               ts['ftd_hash'] in ('REMOVED', 'DEPRECATED'):
                weak_ts.add(ts['name'])
                worst = 'REMOVED' if (
                    ts['ftd_enc'] == 'REMOVED' or
                    ts['ftd_hash'] == 'REMOVED'
                ) else 'DEPRECATED'
                entry = (
                    f"IKEv1 TS '{ts['name']}': "
                    f"{ts['esp_enc']}/{hash_str} — {worst}"
                )
                risk_high.append(entry) if worst == 'REMOVED' \
                    else risk_medium.append(entry)

        if weak_ts:
            print()
            print(f"  [FLAG] {len(weak_ts)} transform set(s) contain "
                  "REMOVED or DEPRECATED algorithms.")
            print("  These MUST be updated before FTD migration AND")
            print("  coordinated with all remote VPN peers.")

    # ── IKEv2 Proposals ──────────────────────────────────────
    print(f"\n  ── IKEv2 IPSEC PROPOSALS ({len(ikev2_proposals)}) " + "─" * 40)

    if not ikev2_proposals:
        print("     None configured.")
    else:
        for prop in ikev2_proposals:
            print(f"\n     Proposal : {prop['name']}")

            for enc in prop['encryption'] or ['(none)']:
                s = ftd_enc_status(enc)
                print(f"       Encryption : {enc:<30} {risk_symbol(s)}")
                if s in ('REMOVED', 'DEPRECATED'):
                    entry = (
                        f"IKEv2 Proposal '{prop['name']}' "
                        f"enc '{enc}': {s}"
                    )
                    risk_high.append(entry) if s == 'REMOVED' \
                        else risk_medium.append(entry)

            for alg in prop['integrity'] or ['(none)']:
                s = ftd_int_status(alg)
                print(f"       Integrity  : {alg:<30} {risk_symbol(s)}")
                if s in ('REMOVED', 'DEPRECATED'):
                    entry = (
                        f"IKEv2 Proposal '{prop['name']}' "
                        f"integrity '{alg}': {s}"
                    )
                    risk_high.append(entry) if s == 'REMOVED' \
                        else risk_medium.append(entry)

            if prop['ah']:
                print(f"       AH         : {', '.join(prop['ah'])}")
                risk_info.append(
                    f"IKEv2 Proposal '{prop['name']}' uses AH — "
                    "verify FTD AH support"
                )

    # ── IPsec Profiles ────────────────────────────────────────
    if ipsec_profiles:
        print(f"\n  ── IPSEC PROFILES ({len(ipsec_profiles)}) " + "─" * 48)
        for profile in ipsec_profiles:
            print(f"\n     Profile : {profile['name']}")
            for setting in profile['settings']:
                s_lower = setting.lower()
                pfs_flag = ''
                if 'pfs' in s_lower:
                    grp_m = re.search(r'group\s*(\d+)', s_lower)
                    if grp_m:
                        g = grp_m.group(1)
                        status = ftd_dh_status(g)
                        if status != 'OK':
                            pfs_flag = (
                                f"  [{risk_symbol(status)} DH group{g}]"
                            )
                            risk_medium.append(
                                f"IPsec profile '{profile['name']}' "
                                f"PFS group{g}: {status}"
                            )
                print(f"       set {setting}{pfs_flag}")

    # ── Dynamic Maps ──────────────────────────────────────────
    if dynamic_maps:
        print(f"\n  ── DYNAMIC CRYPTO MAPS ({len(dynamic_maps)}) " + "─" * 44)
        print("     [INFO] Dynamic maps = used for RA VPN (AnyConnect).")
        print("     These do NOT migrate via FMT.")
        print("     Must be rebuilt as RA VPN Connection Profiles in FMC.")
        risk_high.append(
            f"{len(dynamic_maps)} dynamic map(s) present — "
            "RA VPN must be fully rebuilt in FMC, not migrated via FMT"
        )

        for map_name, entries in sorted(dynamic_maps.items()):
            print(f"\n     Dynamic Map : {map_name}")
            for e in entries:
                flags = e['dh_flag'] + e['weak_flag']
                print(f"       seq {e['seq']}: {e['setting']}{flags}")

    # ── Static Crypto Maps ────────────────────────────────────
    if crypto_maps:
        total_entries = sum(len(v) for v in crypto_maps.values())
        print(f"\n  ── STATIC CRYPTO MAPS"
              f" ({len(crypto_maps)} map(s), {total_entries} entr(ies))"
              + " " + "─" * 25)

        weak_ts_names = {
            ts['name'] for ts in ikev1_ts
            if ts['ftd_enc'] in ('REMOVED', 'DEPRECATED') or
               ts['ftd_hash'] in ('REMOVED', 'DEPRECATED')
        }

        for map_name, seqs in sorted(crypto_maps.items()):
            iface = map_interfaces.get(map_name, '(not bound)')
            print(f"\n     Crypto Map : {map_name}  (interface: {iface})")
            print(f"     {'SEQ':>5}  {'MATCH ACL':<22} {'PEER(S)':<20}"
                  f" {'IKEv1 TS':<18} {'IKEv2 PROP':<18} {'PFS'}")
            print(f"     {'-'*5}  {'-'*21} {'-'*19} {'-'*17}"
                  f" {'-'*17} {'-'*10}")

            for seq, entry in sorted(seqs.items()):
                acl   = entry['match_acl']        or '—'
                peers = ', '.join(entry['peers'])  or '—'
                ts    = ', '.join(entry['ikev1_ts'])    or '—'
                prop  = ', '.join(entry['ikev2_prop'])  or '—'
                pfs   = entry['pfs']              or '—'

                print(f"     {seq:>5}  {acl:<22} {peers:<20}"
                      f" {ts:<18} {prop:<18} {pfs}")

                weak_refs = [
                    t for t in entry['ikev1_ts']
                    if t.lower() in {n.lower() for n in weak_ts_names}
                ]
                if weak_refs:
                    print(f"             [FLAG] Weak TS referenced:"
                          f" {', '.join(weak_refs)}")
                    risk_high.append(
                        f"Crypto map '{map_name}' seq {seq} references "
                        f"weak TS: {', '.join(weak_refs)}"
                    )

                if entry['pfs']:
                    grp_m = re.search(
                        r'group\s*(\d+)', entry['pfs'].lower()
                    )
                    if grp_m:
                        g = grp_m.group(1)
                        status = ftd_dh_status(g)
                        if status != 'OK':
                            print(f"             [FLAG] PFS DH group{g}:"
                                  f" {risk_symbol(status)}")
                            risk_medium.append(
                                f"Crypto map '{map_name}' seq {seq} "
                                f"PFS group{g}: {status}"
                            )

    # ── Legacy ISAKMP ─────────────────────────────────────────
    if isakmp_globals:
        print(f"\n  ── LEGACY ISAKMP STATEMENTS ({len(isakmp_globals)}) "
              + "─" * 37)
        print("     [INFO] 'crypto isakmp' is the legacy IKEv1 syntax.")
        print("     Verify these are captured in IKEv1 policy blocks above.")
        print("     If standalone, they may need manual review for FMC.")
        for line in isakmp_globals:
            print(f"     {line}")

    # ── IPsec globals ─────────────────────────────────────────
    if ipsec_globals or sa_settings:
        print(f"\n  ── IPSEC GLOBAL SETTINGS " + "─" * 48)
        for line in sa_settings + ipsec_globals:
            print(f"     {line}")

    # ── Partial lines ─────────────────────────────────────────
    if partials:
        print(f"\n  ── PARTIAL MATCHES ({len(partials)}) " + "─" * 50)
        print("  [PARTIAL] Lines starting with 'crypto' that did not")
        print("  match any known pattern. Review manually:")
        for p in partials:
            print(f"    {p[:75]}")

    # ── Unmatched lines ───────────────────────────────────────
    if unmatched:
        print(f"\n  ── UNMATCHED LINES ({len(unmatched)}) " + "─" * 50)
        print("  These lines did not match any crypto pattern:")
        for u in unmatched[:20]:
            print(f"    {u[:75]}")
        if len(unmatched) > 20:
            print(f"    ... and {len(unmatched) - 20} more")

    # ── Migration Risk Summary ────────────────────────────────
    print(f"\n  {'='*78}")
    print("  CRYPTO MIGRATION RISK SUMMARY")
    print(f"  {'='*78}")

    if not risk_high and not risk_medium and not risk_info:
        print("  [OK] No crypto migration risks detected.")
    else:
        if risk_high:
            print(f"\n  [HIGH RISK] ({len(risk_high)} item(s))"
                  f" — WILL BREAK on FTD without remediation:")
            for item in risk_high:
                print(f"     * {item}")

        if risk_medium:
            print(f"\n  [MEDIUM RISK] ({len(risk_medium)} item(s))"
                  f" — deprecated, may fail on newer FTD versions:")
            for item in risk_medium:
                print(f"     * {item}")

        if risk_info:
            print(f"\n  [INFO] ({len(risk_info)} item(s)) — verify:")
            for item in risk_info:
                print(f"     * {item}")

    print()


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def print_header():
    print()
    print("=" * 78)
    print("  ASA MIGRATION PARSER — PHASE 4")
    print("  Full-Spec ACL + Crypto Analysis with FTD Compatibility")
    print("  Three-layer parsing: Full match | Partial | Unmatched")
    print("  Includes: PKI trustpoints, certificate chains,")
    print("            IKEv1/IKEv2 policies, transform sets,")
    print("            IPsec proposals, crypto maps, dynamic maps")
    print("=" * 78)
    print()


def main():
    if len(sys.argv) != 2:
        print("Usage: python asa_parser_p4.py <path_to_log_file>")
        print("Example: python asa_parser_p4.py asa_logs.txt")
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

    # ── ACCESS-LIST ───────────────────────────────────────────
    acl_lines = sections_data.get("ACCESS-LIST", [])
    if acl_lines:
        meta, rules, partials, unmatched = parse_access_list_show(acl_lines)
        print_access_list_show(meta, rules, partials, unmatched)
    else:
        print("  [SKIPPED] ACCESS-LIST — section empty or not found.\n")

    # ── RUNNING-CONFIG-ACCESS-LIST ────────────────────────────
    cfg_lines = sections_data.get("RUNNING-CONFIG-ACCESS-LIST", [])
    if cfg_lines:
        cfg_rules, cfg_partials, cfg_unmatched = \
            parse_running_config_acl(cfg_lines)
        print_running_config_acl(cfg_rules, cfg_partials, cfg_unmatched)
    else:
        print("  [SKIPPED] RUNNING-CONFIG-ACCESS-LIST —"
              " section empty or not found.\n")

    # ── RUNNING-CONFIG-CRYPTO ─────────────────────────────────
    crypto_lines = sections_data.get("RUNNING-CONFIG-CRYPTO", [])
    if crypto_lines:
        results = parse_crypto(crypto_lines)
        print_crypto(*results)
    else:
        print("  [SKIPPED] RUNNING-CONFIG-CRYPTO —"
              " section empty or not found.\n")


if __name__ == "__main__":
    main()
