# =============================================================================
# utils/fs_utils.py — Generic APK directory detection
#
# Supports both:
#   - apktool output: smali/, res/, AndroidManifest.xml at root
#   - jadx output  : sources/, resources/, AndroidManifest.xml at root
#                    or nested under resources/
# =============================================================================

import os
import warnings


def find_android_manifest(apk_root):
    """
    Locate AndroidManifest.xml within the decompiled APK directory.

    Strategy:
      1. Check apk_root directly (standard apktool location)
      2. Walk subdirectories as fallback (jadx may nest it under resources/)

    Returns:
        Absolute path string, or None if not found.
    """
    # Fast path: apktool places it at the root
    direct = os.path.join(apk_root, "AndroidManifest.xml")
    if os.path.isfile(direct):
        return direct

    # Fallback: jadx may place it inside resources/
    for dirpath, _, files in os.walk(apk_root):
        if "AndroidManifest.xml" in files:
            return os.path.join(dirpath, "AndroidManifest.xml")

    return None


def find_java_sources_dir(apk_root):
    """
    Locate the directory containing Java source files (.java).

    Detection priority:
      1. jadx-style: <root>/sources/
      2. apktool-style: smali/ directories (smali, smali_classes2, …)
         — NOTE: smali is bytecode, not .java; we return it anyway so
           rules that only scan .java files will gracefully find nothing.
      3. Recursive search for any 'sources' directory

    Returns:
        Absolute path string, or None if not found.
    """
    # 1. JADX primary output
    candidate = os.path.join(apk_root, "sources")
    if os.path.isdir(candidate):
        return candidate

    # 2. Recursive search for a 'sources' directory
    for dirpath, dirs, _ in os.walk(apk_root):
        if "sources" in dirs:
            return os.path.join(dirpath, "sources")

    # 3. Apktool smali fallback (rules will find no .java but won't crash)
    smali = os.path.join(apk_root, "smali")
    if os.path.isdir(smali):
        warnings.warn(
            "[fs_utils] Only smali bytecode found — Java source rules "
            "will report PASS by default (no .java files to scan).",
            stacklevel=2
        )
        return smali

    # 4. First smali_classesN variant
    for dirpath, dirs, _ in os.walk(apk_root):
        for d in sorted(dirs):
            if d.startswith("smali"):
                warnings.warn(
                    f"[fs_utils] Using '{d}' as sources directory (smali only).",
                    stacklevel=2
                )
                return os.path.join(dirpath, d)

    return None


def find_res_dir(apk_root):
    """
    Locate the res/ directory containing XML resource files.

    Detection priority:
      1. <root>/res/  — standard apktool output
      2. <root>/resources/res/  — jadx resource bundle
      3. Recursive search for 'res' directory

    Returns:
        Absolute path string of the res/ directory, or None if not found.
    """
    # 1. Apktool standard location
    candidate = os.path.join(apk_root, "res")
    if os.path.isdir(candidate):
        return candidate

    # 2. JADX nests res/ inside resources/
    jadx_candidate = os.path.join(apk_root, "resources", "res")
    if os.path.isdir(jadx_candidate):
        return jadx_candidate

    # 3. Generic recursive search
    for dirpath, dirs, _ in os.walk(apk_root):
        if "res" in dirs:
            return os.path.join(dirpath, "res")

    return None


def find_xml_resource(res_dir, *relative_parts):
    """
    Resolve a path relative to the res/ directory.

    Example:
        find_xml_resource(res_dir, "xml", "network_security_config.xml")

    Returns:
        Absolute path if the file exists, else None.
    """
    if not res_dir:
        return None
    path = os.path.join(res_dir, *relative_parts)
    return path if os.path.isfile(path) else None
