# =============================================================================
# rules/broken_symmetric_encryption_rule.py
# MASTG-BEST-0005 | MASTG-TEST-0232
# Category: CRYPTO | Severity: HIGH
# =============================================================================

import os
import re

# Detects Cipher.getInstance("...") calls and captures the transformation string
CIPHER_GET_REGEX   = re.compile(r'Cipher\.getInstance\("([^"]+)"\)')
# Broad crypto usage markers used to distinguish "no crypto at all" from "secure crypto"
CIPHER_IMPORT_REGEX = re.compile(r'javax\.crypto\.Cipher')
AES_ANY_REGEX       = re.compile(r'\bAES\b')


def run(context):
    """
    MASTG-BEST-0005 — Detect insecure symmetric encryption modes (ECB).

    Scans all .java files in the sources directory for:
      - Cipher.getInstance("AES")  → defaults to ECB, insecure
      - Cipher.getInstance("AES/ECB/...")  → explicitly ECB

    RSA and other asymmetric algorithms are excluded to avoid false positives.

    Result is independent of package name — any ECB usage in app code is a FAIL.
    """
    sources_path = context.get("sources_path")

    if not sources_path or not os.path.isdir(sources_path):
        return (
            "PASS",
            "Java source directory not available for analysis",
            "HIGH",
            "MASTG-BEST-0005",
            "CRYPTO"
        )

    ecb_findings   = []   # confirmed ECB / bare AES usages
    crypto_present = False  # any javax.crypto.Cipher usage found at all

    for dirpath, _, files in os.walk(sources_path):
        for fname in files:
            if not fname.endswith(".java"):
                continue

            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            # Check for any crypto usage to track PASS quality
            if CIPHER_IMPORT_REGEX.search(content) or AES_ANY_REGEX.search(content):
                crypto_present = True

            # Check each Cipher.getInstance() call for insecure modes
            for transformation in CIPHER_GET_REGEX.findall(content):
                transformation = transformation.strip()

                # Skip asymmetric (RSA, ...) — not affected by mode issues
                if transformation.upper().startswith("RSA"):
                    continue

                if transformation == "AES" or "/ECB/" in transformation.upper():
                    ecb_findings.append(
                        f"{fpath} → Cipher.getInstance(\"{transformation}\")"
                    )

    # ---- Decision ----
    if ecb_findings:
        return (
            "FAIL",
            {"ecb_usages": ecb_findings},
            "HIGH",
            "MASTG-BEST-0005",
            "CRYPTO"
        )

    if crypto_present:
        return (
            "PASS",
            "Cryptographic APIs detected — no ECB or bare AES mode found",
            "HIGH",
            "MASTG-BEST-0005",
            "CRYPTO"
        )

    return (
        "PASS",
        "No javax.crypto.Cipher / AES usage detected in source code",
        "HIGH",
        "MASTG-BEST-0005",
        "CRYPTO"
    )
