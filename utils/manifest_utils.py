# =============================================================================
# utils/manifest_utils.py — AndroidManifest helpers
# =============================================================================

from mastg_scanner.config import ANDROID_NS


def get_min_sdk(root):
    """
    Extract minSdkVersion from <uses-sdk> in the parsed manifest.

    Returns:
        Integer minSdkVersion, or None if not declared.
    """
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        raw = uses_sdk.attrib.get(ANDROID_NS + "minSdkVersion")
        if raw and raw.isdigit():
            return int(raw)
    return None


def get_target_sdk(root):
    """
    Extract targetSdkVersion from <uses-sdk>.

    Returns:
        Integer targetSdkVersion, or None if not declared.
    """
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        raw = uses_sdk.attrib.get(ANDROID_NS + "targetSdkVersion")
        if raw and raw.isdigit():
            return int(raw)
    return None


def has_post_notifications_permission(root):
    """
    Check whether the app declares the POST_NOTIFICATIONS permission.
    Required for MASTG-BEST-0027 evaluation on API 33+.
    """
    for perm in root.findall("uses-permission"):
        name = perm.attrib.get(ANDROID_NS + "name", "")
        if name == "android.permission.POST_NOTIFICATIONS":
            return True
    return False
