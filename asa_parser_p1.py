# ============================================================
# ASA Migration Parser - Phase 1: Section Detection
# ============================================================
# PURPOSE:
#   Reads a structured ASA log file containing section headers
#   in the format:  ! ===SECTION: <NAME>===
#   Detects all sections, reports line numbers, and prints
#   a clean table of contents confirming file structure.
#
# USAGE:
#   python asa_parser_p1.py <path_to_log_file>
#   Example: python asa_parser_p1.py asa_logs.txt
#
# OUTPUT:
#   - Total line count of file
#   - Ordered table of contents with section name + line number
#   - Warning for any expected sections that are missing
#   - Warning if file appears empty or no sections found
#
# ASSUMPTIONS:
#   - Section headers match exactly: ! ===SECTION: <NAME>===
#   - Header is the only content on that line
#   - File is plain text, UTF-8 or ASCII encoded
#   - No assumption is made about content between headers
# ============================================================

import re
import sys
import os

# ── Expected sections based on your log file structure ──────
# If a section is missing from the file, the script will warn you.
# Update this list if you add or rename sections.
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

# ── Regex pattern to match your exact header format ─────────
# Matches:  ! ===SECTION: <NAME>===
# Captures: the section name between ": " and "==="
# Strips leading/trailing whitespace from the captured name
SECTION_PATTERN = re.compile(
    r'^!\s*===SECTION:\s*([A-Z0-9_\-]+)\s*===$',
    re.IGNORECASE
)


def parse_sections(filepath):
    """
    Reads the log file line by line.
    Returns a list of tuples: (section_name, line_number)
    Line numbers are 1-indexed to match Notepad++ display.
    """
    sections_found = []

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, start=1):
            line_stripped = line.strip()
            match = SECTION_PATTERN.match(line_stripped)
            if match:
                section_name = match.group(1).upper().strip()
                sections_found.append((section_name, line_num))

    return sections_found


def print_table_of_contents(sections_found, total_lines):
    """
    Prints a formatted table of contents to the terminal.
    """
    print("=" * 60)
    print("  ASA LOG FILE — SECTION DETECTION REPORT")
    print("=" * 60)
    print(f"  Total lines in file : {total_lines}")
    print(f"  Sections detected   : {len(sections_found)}")
    print("=" * 60)

    if not sections_found:
        print("\n  [ERROR] No sections detected.")
        print("  Verify your header format matches exactly:")
        print("  ! ===SECTION: SECTION-NAME===")
        return

    print(f"\n  {'#':<5} {'LINE':<8} {'SECTION NAME'}")
    print(f"  {'-'*4} {'-'*7} {'-'*35}")

    for idx, (name, line_num) in enumerate(sections_found, start=1):
        print(f"  {idx:<5} {line_num:<8} {name}")


def check_missing_sections(sections_found):
    """
    Compares detected sections against the expected list.
    Prints warnings for any expected sections not found in file.
    """
    found_names = {name for name, _ in sections_found}
    missing = [s for s in EXPECTED_SECTIONS if s not in found_names]
    unexpected = [s for s in found_names if s not in EXPECTED_SECTIONS]

    print("\n" + "=" * 60)
    print("  SECTION VALIDATION")
    print("=" * 60)

    if not missing:
        print("  [OK] All expected sections detected.")
    else:
        print(f"  [WARNING] {len(missing)} expected section(s) NOT found:")
        for m in missing:
            print(f"