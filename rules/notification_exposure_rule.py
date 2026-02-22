# =============================================================================
# rules/notification_exposure_rule.py
# MASTG-BEST-0027 | MASTG-TEST-0315
# Category: PRIVACY | Severity: MEDIUM
# =============================================================================

import os
import re

# Notification API usage markers
NOTIFICATION_USAGE = re.compile(
    r'Notification(Compat)?\.Builder'
    r'|setContentTitle'
    r'|setContentText'
    r'|\.notify\s*\(',
    re.IGNORECASE
)

# Lock-screen visibility settings
VISIBILITY_PRIVATE = re.compile(r'VISIBILITY_PRIVATE',  re.IGNORECASE)
VISIBILITY_SECRET  = re.compile(r'VISIBILITY_SECRET',   re.IGNORECASE)
VISIBILITY_PUBLIC  = re.compile(r'VISIBILITY_PUBLIC',   re.IGNORECASE)

# Heuristic keywords that indicate sensitive notification content
SENSITIVE_KEYWORDS = re.compile(
    r'\b(otp|one[- ]?time|verification[\s_]?code|password|pin\b|'
    r'balance|amount|transaction|credit\s?card|debit\s?card|'
    r'cvv|account\s?number|₹|\$\d)\b',
    re.IGNORECASE
)


def run(context):
    """
    MASTG-BEST-0027 — Prevent Sensitive Data Exposure in Notifications.

    Evaluation logic (per MASTG-TEST-0315):
      1. No notification usage → PASS
      2. Notifications without sensitive content → PASS
      3. Sensitive content + lock-screen protected → PASS
      4. Sensitive content + no protection + fail condition met → FAIL

    Fail condition depends on:
      - minSdk >= 33 AND POST_NOTIFICATIONS declared → app actively sends notifs
      - minSdk <= 32 → permission not required, notifications may be sent
    """
    sources_path          = context.get("sources_path")
    min_sdk               = context.get("min_sdk")          # int or None
    post_notif_declared   = context.get("post_notifications_declared", False)

    if not sources_path or not os.path.isdir(sources_path):
        return (
            "PASS",
            "Java source not available for notification analysis",
            "MEDIUM",
            "MASTG-BEST-0027",
            "PRIVACY"
        )

    notification_used = False
    sensitive_content = False
    lockscreen_safe   = False
    explicit_public   = False

    for dirpath, _, files in os.walk(sources_path):
        for fname in files:
            if not fname.endswith(".java"):
                continue
            try:
                with open(os.path.join(dirpath, fname), "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            if NOTIFICATION_USAGE.search(content):
                notification_used = True

            if SENSITIVE_KEYWORDS.search(content):
                sensitive_content = True

            if VISIBILITY_PRIVATE.search(content) or VISIBILITY_SECRET.search(content):
                lockscreen_safe = True

            if VISIBILITY_PUBLIC.search(content):
                explicit_public = True

    # No notification code found at all
    if not notification_used:
        return ("PASS", "No notification usage detected", "MEDIUM",
                "MASTG-BEST-0027", "PRIVACY")

    # Notifications found but no sensitive content
    if not sensitive_content:
        return ("PASS", "Notifications used without sensitive content", "MEDIUM",
                "MASTG-BEST-0027", "PRIVACY")

    # Determine whether the app actively sends notifications
    fail_condition = False
    if min_sdk is not None:
        if min_sdk >= 33 and post_notif_declared:
            fail_condition = True     # API 33+: needs explicit permission
        elif min_sdk <= 32:
            fail_condition = True     # API ≤ 32: notifications are free

    if fail_condition:
        # Lock-screen is protected — pass
        if lockscreen_safe and not explicit_public:
            return (
                "PASS",
                "Sensitive notifications protected on lock screen "
                "(VISIBILITY_PRIVATE or VISIBILITY_SECRET)",
                "MEDIUM",
                "MASTG-BEST-0027",
                "PRIVACY"
            )
        return (
            "FAIL",
            "Sensitive notification content may be visible on the lock screen",
            "MEDIUM",
            "MASTG-BEST-0027",
            "PRIVACY"
        )

    return ("PASS", "Notification exposure conditions not met", "MEDIUM",
            "MASTG-BEST-0027", "PRIVACY")
