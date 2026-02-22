# =============================================================================
# rules/webview_local_file_access_rule.py
# MASTG-BEST-0011 | MASTG-TEST-0252
# Category: PLATFORM | Severity: HIGH
# =============================================================================

import os
import re

WEBVIEW          = re.compile(r'\bWebView\b')

JS_TRUE          = re.compile(r'setJavaScriptEnabled\s*\(\s*true\s*\)')
JS_FALSE         = re.compile(r'setJavaScriptEnabled\s*\(\s*false\s*\)')

ALLOW_FILE_TRUE  = re.compile(r'setAllowFileAccess\s*\(\s*true\s*\)')
ALLOW_FILE_FALSE = re.compile(r'setAllowFileAccess\s*\(\s*false\s*\)')

FILE_URL_TRUE    = re.compile(r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)')
FILE_URL_FALSE   = re.compile(r'setAllowFileAccessFromFileURLs\s*\(\s*false\s*\)')

UNIVERSAL_TRUE   = re.compile(r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)')
UNIVERSAL_FALSE  = re.compile(r'setAllowUniversalAccessFromFileURLs\s*\(\s*false\s*\)')


def run(context):
    """
    MASTG-BEST-0011 — Securely Load File Content in WebViews.

    Default Android behaviors matter here (controlled by minSdkVersion):
      - setAllowFileAccess defaults to true  for minSdk < 30
      - setAllowFileAccessFromFileURLs defaults to true for minSdk < 16

    FAIL if ALL of the following apply:
      - JavaScript is enabled
      - File access is enabled (explicit or default via minSdk)
      - File URL or universal access is enabled (explicit or default via minSdk)

    PASS if any mitigating control is present or secure defaults apply.
    """
    sources_path = context.get("sources_path")
    min_sdk      = context.get("min_sdk") or 1   # treat None as worst-case (1)

    if not sources_path or not os.path.isdir(sources_path):
        return (
            "PASS",
            "Java source not available for WebView file access analysis",
            "MEDIUM",
            "MASTG-BEST-0011",
            "PLATFORM"
        )

    risky_files = []
    safe_files  = []

    for dirpath, _, files in os.walk(sources_path):
        for fname in files:
            if not fname.endswith(".java"):
                continue
            try:
                with open(os.path.join(dirpath, fname), "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            if not WEBVIEW.search(content):
                continue

            fpath = os.path.join(dirpath, fname)

            js_on  = JS_TRUE.search(content)
            js_off = JS_FALSE.search(content)

            file_on  = ALLOW_FILE_TRUE.search(content)
            file_off = ALLOW_FILE_FALSE.search(content)

            # Default: file access enabled for minSdk < 30
            file_default_on = not file_off and min_sdk < 30

            furl_on  = FILE_URL_TRUE.search(content)
            furl_off = FILE_URL_FALSE.search(content)

            univ_on  = UNIVERSAL_TRUE.search(content)
            univ_off = UNIVERSAL_FALSE.search(content)

            # Default: file URL access enabled for minSdk < 16
            furl_default_on = not furl_off and min_sdk < 16

            # --- Mitigations (PASS immediately) ---
            if js_off:
                safe_files.append(fpath)
                continue

            if file_off and furl_off and univ_off:
                safe_files.append(fpath)
                continue

            # --- FAIL condition ---
            file_access_risky = file_on or file_default_on
            url_access_risky  = furl_on or univ_on or furl_default_on

            if js_on and file_access_risky and url_access_risky:
                risky_files.append(fpath)

    if risky_files:
        return (
            "FAIL",
            {"unsafe_webview_local_file_access": risky_files},
            "HIGH",
            "MASTG-BEST-0011",
            "PLATFORM"
        )

    if safe_files:
        return (
            "PASS",
            "WebView local file access securely restricted",
            "MEDIUM",
            "MASTG-BEST-0011",
            "PLATFORM"
        )

    return (
        "PASS",
        "No risky WebView local file access configuration detected",
        "MEDIUM",
        "MASTG-BEST-0011",
        "PLATFORM"
    )
