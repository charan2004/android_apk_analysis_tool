#!/usr/bin/env python3
# =============================================================================
# mastg_scanner/main.py — Entry point for the Generic MASTG Android Scanner
#
# Usage:
#   python3 -m mastg_scanner.main <decompiled_apk_directory>
#   # or from project root:
#   python3 mastg_scanner/main.py <decompiled_apk_directory>
# =============================================================================

import sys
import os
import warnings
import xml.etree.ElementTree as ET
from collections import defaultdict

# Allow running as `python3 mastg_scanner/main.py` from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mastg_scanner.config import TOOL_NAME, TOOL_VERSION, CATEGORY_ORDER, SEVERITY_WEIGHT
from mastg_scanner.engine.runner import run_all
from mastg_scanner.utils.fs_utils import find_android_manifest, find_java_sources_dir, find_res_dir
from mastg_scanner.utils.manifest_utils import get_min_sdk


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _print_banner(apk_root):
    width = 70
    print("=" * width)
    print(f"  {TOOL_NAME}  v{TOOL_VERSION}")
    print(f"  Target : {os.path.abspath(apk_root)}")
    print("=" * width)


def _format_evidence(evidence):
    """
    Pretty-print evidence, which may be a string, list, or dict.
    Returns a list of formatted lines.
    """
    lines = []
    if isinstance(evidence, dict):
        for key, val in evidence.items():
            label = key.replace("_", " ").title()
            if isinstance(val, list):
                if val:
                    lines.append(f"    {label}:")
                    for item in val:
                        lines.append(f"      • {item}")
            else:
                lines.append(f"    {label}: {val}")
    elif isinstance(evidence, list):
        for item in evidence:
            lines.append(f"    • {item}")
    else:
        lines.append(f"    {evidence}")
    return lines


def _calculate_score(category_scores):
    """
    Compute an overall 0–100 score weighted by severity.

    Each check contributes weight × 1 to the max; weight × 1 if PASS.
    """
    total_weight  = 0
    earned_weight = 0

    for _cat, checks in category_scores.items():
        for status, severity in checks:
            w = SEVERITY_WEIGHT.get(severity, 1)
            total_weight  += w
            if status == "PASS":
                earned_weight += w

    if total_weight == 0:
        return 100
    return round((earned_weight / total_weight) * 100)


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    # ---- 1. Argument validation ----
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <decompiled_apk_directory>")
        sys.exit(1)

    apk_root = sys.argv[1]

    if not os.path.isdir(apk_root):
        print(f"[ERROR] Not a directory: {apk_root}")
        sys.exit(1)

    # ---- 2. Discover components ----
    manifest_path = find_android_manifest(apk_root)
    sources_path  = find_java_sources_dir(apk_root)
    res_dir       = find_res_dir(apk_root)

    if not manifest_path:
        print("[ERROR] AndroidManifest.xml not found. "
              "Ensure the directory is a valid apktool/jadx output.")
        sys.exit(1)

    if not sources_path:
        warnings.warn(
            "[WARN] Java sources directory not found — "
            "source-code rules will report PASS by default.",
            stacklevel=1
        )

    if not res_dir:
        warnings.warn(
            "[WARN] res/ directory not found — "
            "resource-based rules may be skipped.",
            stacklevel=1
        )

    # ---- 3. Parse AndroidManifest.xml ----
    try:
        tree        = ET.parse(manifest_path)
        xml_root    = tree.getroot()
        application = xml_root.find("application")
        package_name = xml_root.attrib.get("package", "")
        min_sdk      = get_min_sdk(xml_root)
    except ET.ParseError as exc:
        print(f"[ERROR] Failed to parse AndroidManifest.xml: {exc}")
        sys.exit(1)

    if application is None:
        print("[ERROR] <application> element not found in AndroidManifest.xml")
        sys.exit(1)

    # ---- 4. Build context ----
    context = {
        "xml_root":     xml_root,
        "application":  application,
        "package_name": package_name,
        "sources_path": sources_path,
        "res_dir":      res_dir,
        "min_sdk":      min_sdk,
        "apk_root":     apk_root,
    }

    # ---- 5. Print banner ----
    _print_banner(apk_root)
    print(f"\n  Package  : {package_name or '(unknown)'}")
    print(f"  Min SDK  : {min_sdk or '(not declared)'}")
    print(f"  Sources  : {sources_path or '(not found)'}")
    print(f"  Res Dir  : {res_dir or '(not found)'}")
    print()

    # ---- 6. Execute all rules ----
    results = run_all(context)

    # ---- 7. Print per-rule output ----
    print(f"{'─' * 70}")
    print("  Security Check Results")
    print(f"{'─' * 70}\n")

    category_scores = defaultdict(list)

    for rule_name, (status, evidence, severity, mastg_id, category) in results:
        symbol = "✓" if status == "PASS" else ("✗" if status == "FAIL" else "!")
        status_label = f"[{symbol}] {status}"

        print(f"{status_label}  {rule_name}  ({severity})")
        print(f"    MASTG ID : {mastg_id}")
        print(f"    Category : {category}")
        print("    Evidence :")
        for line in _format_evidence(evidence):
            print(line)
        print()

        category_scores[category].append((status, severity))

    # ---- 8. Category summary ----
    print(f"{'─' * 70}")
    print("  Category Summary")
    print(f"{'─' * 70}")

    # Print in defined order, then any unlisted categories
    ordered_cats = CATEGORY_ORDER + [
        c for c in category_scores if c not in CATEGORY_ORDER
    ]

    for cat in ordered_cats:
        if cat not in category_scores:
            continue
        checks   = category_scores[cat]
        total    = len(checks)
        passed   = sum(1 for s, _ in checks if s == "PASS")
        pct      = round((passed / total) * 100) if total else 0
        bar_fill = "█" * (passed)
        bar_empty = "░" * (total - passed)
        print(f"  {cat:<12} {passed:>2}/{total}  [{bar_fill}{bar_empty}]  ({pct}%)")

    # ---- 9. Overall score ----
    score = _calculate_score(category_scores)
    total_checks  = len(results)
    passed_checks = sum(1 for _, (s, *_) in results if s == "PASS")

    print(f"\n{'─' * 70}")
    print(f"  Overall Score  : {score} / 100")
    print(f"  Checks Passed  : {passed_checks} / {total_checks}")
    if score >= 80:
        rating = "GOOD ✓"
    elif score >= 50:
        rating = "NEEDS IMPROVEMENT ⚠"
    else:
        rating = "HIGH RISK ✗"
    print(f"  Risk Rating    : {rating}")
    print(f"{'─' * 70}\n")


if __name__ == "__main__":
    main()
