import os
import subprocess
import xml.etree.ElementTree as ET
import sys
import tempfile

def decompile_apk(apk_path, output_dir):
    """Decompile APK using apktool."""
    try:
        subprocess.run(["apktool", "d", apk_path, "-o", output_dir, "-f"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to decompile APK: {e}")
        return False

def analyze_manifest(manifest_path):
    """Parse AndroidManifest.xml for exported activities."""
    if not os.path.exists(manifest_path):
        print(f"[-] Manifest not found: {manifest_path}")
        return None

    tree = ET.parse(manifest_path)
    root = tree.getroot()

    # Namespace handling (AndroidManifest.xml uses xmlns)
    ns = {'android': 'http://schemas.android.com/apk/res/android'}

    package_name = root.get('package')
    permissions = {}
    activities = []

    # Extract declared permissions
    for perm in root.findall("uses-permission"):
        perm_name = perm.get(f"{{{ns['android']}}}name")
        if perm_name:
            permissions[perm_name] = "normal"  # Default level (can be refined)

    # Extract activities and their properties
    for activity in root.findall(".//activity", ns):
        activity_name = activity.get(f"{{{ns['android']}}}name")
        exported = activity.get(f"{{{ns['android']}}}exported", "false").lower() == "true"
        permission = activity.get(f"{{{ns['android']}}}permission")

        # Check intent-filter (implicit export)
        intent_filters = activity.findall("intent-filter", ns)
        has_intent_filters = len(intent_filters) > 0

        # If 'exported' is not explicitly set, intent-filters make it exported by default
        final_exported = exported or (has_intent_filters and "exported" not in activity.attrib)

        activities.append({
            "name": activity_name,
            "exported": final_exported,
            "permission": permission,
            "protection_level": permissions.get(permission, "none")
        })

    return {
        "package": package_name,
        "activities": activities,
        "permissions": permissions
    }

def generate_adb_command(package, activity):
    """Generate ADB command to launch an activity."""
    return f"adb shell am start -n {package}/{activity}"

def analyze_apk(apk_path):
    """Main function to analyze APK."""
    if not os.path.isfile(apk_path):
        print(f"[-] File not found: {apk_path}")
        return

    # Decompile APK to a temp directory
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"[*] Decompiling APK to: {temp_dir}")
        if not decompile_apk(apk_path, temp_dir):
            return

        manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
        manifest_data = analyze_manifest(manifest_path)

        if not manifest_data:
            return

        print(f"\n[+] Package Name: {manifest_data['package']}")

        for activity in manifest_data["activities"]:
            print(f"\n[*] Activity: {activity['name']}")
            print(f"    - Exported: {activity['exported']}")
            print(f"    - Permission: {activity['permission'] or 'None'}")
            print(f"    - Protection Level: {activity['protection_level']}")

            if activity['exported'] and (not activity['permission'] or "signature" not in activity['protection_level']):
                print(f"    - [!] ADB Command: {generate_adb_command(manifest_data['package'], activity['name'])}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_apk.py <path_to_apk>")
    else:
        analyze_apk(sys.argv[1])
