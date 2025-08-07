import os
import sys
import subprocess
import xml.etree.ElementTree as ET

PERMISSION_GUIDE = {
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "risk": "App can write files to shared external storage.",
        "test": [
            "Use adb to inspect /sdcard/ and /storage/emulated/0/ for sensitive files.",
            "Look for logs, tokens, DBs, or exported files."
        ],
        "tools": ["adb", "file explorers", "grep"],
        "note": "External storage is world-readable on older Android versions."
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "risk": "Can read user files on SD card (images, downloads, etc).",
        "test": [
            "Look for data leaks by browsing files the app accesses.",
            "Monitor runtime file access via `logcat` or dynamic analysis."
        ],
        "tools": ["Frida", "adb", "logcat"],
        "note": "May access unrelated apps' files on older Android versions."
    },
    "android.permission.INTERNET": {
        "risk": "Can send or receive data over the internet.",
        "test": [
            "Run app with proxy (Burp, mitmproxy) to inspect requests.",
            "Look for plaintext credentials, tokens, or APIs."
        ],
        "tools": ["Burp Suite", "mitmproxy", "jadx"],
        "note": "Check for insecure HTTP usage or broken certificate pinning."
    },
    "android.permission.CAMERA": {
        "risk": "Can take photos or record video without user knowing.",
        "test": [
            "Monitor background camera usage.",
            "Check for silent camera triggers in code."
        ],
        "tools": ["Frida", "jadx", "logcat"],
        "note": "Look for abuse scenarios like silent surveillance."
    },
    "android.permission.RECORD_AUDIO": {
        "risk": "App can record user audio.",
        "test": [
            "Use runtime hooks to detect background audio recording.",
            "Inspect code for hidden microphone usage."
        ],
        "tools": ["Frida", "jadx", "objection"],
        "note": "Especially critical in conferencing or social apps."
    },
    "android.permission.READ_SMS": {
        "risk": "Can read received SMS (e.g., OTPs).",
        "test": [
            "Try to trigger OTP input or SMS listeners.",
            "Check for insecure SMS parsing logic."
        ],
        "tools": ["adb", "jadx"],
        "note": "Useful in MFA bypass or sensitive data theft."
    },
    "android.permission.RECEIVE_SMS": {
        "risk": "Can intercept incoming SMS messages.",
        "test": [
            "Check if app automatically reads and parses OTPs.",
            "Test for broadcast receiver hijacking (on older versions)."
        ],
        "tools": ["adb", "Frida"],
        "note": "SMS-based 2FA may be vulnerable if auto-read is used."
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "risk": "Can draw overlays (used in phishing overlays).",
        "test": [
            "Check if overlays can spoof UI (e.g., login screen).",
            "Try launching phishing overlays using Frida."
        ],
        "tools": ["Frida", "objection"],
        "note": "Often abused in malware to trick users."
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "risk": "Can get precise GPS location.",
        "test": [
            "Inspect if app sends location data to external servers.",
            "Test privacy policy and consent flow."
        ],
        "tools": ["mitmproxy", "jadx"],
        "note": "Location tracking abuse can lead to privacy violations."
    }
}

def decompile_apk(apk_path, output_dir="decompiled_apk"):
    subprocess.run(["apktool", "d", "-f", apk_path, "-o", output_dir], check=True)
    return output_dir

def parse_permissions(manifest_path):
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    perms = []
    for perm in root.findall("uses-permission"):
        name = perm.get("{http://schemas.android.com/apk/res/android}name")
        if name:
            perms.append(name)
    return perms
def explain_permissions(perms):
    print("\n" + "="*60)
    print("[+] Pentest Analysis of Permissions")
    print("="*60 + "\n")

    for perm in perms:
        print("─" * 60)
        print(f"[+] Permission: {perm}")
        print("─" * 60)

        if perm in PERMISSION_GUIDE:
            info = PERMISSION_GUIDE[perm]
            print(f"  → Risk : {info['risk']}")
            print("  → Test :")
            for test in info['test']:
                print(f"      • {test}")
            print("  → Tools:")
            print(f"      • {', '.join(info['tools'])}")
            print(f"  → Note :\n      {info['note']}")
        else:
            print("  → No specific guidance found. Consider researching manually.")
        print()

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <apk_file>")
        sys.exit(1)

    apk_file = sys.argv[1]
    if not os.path.isfile(apk_file):
        print("[-] APK file does not exist.")
        sys.exit(1)

    decompiled = decompile_apk(apk_file)
    manifest_path = os.path.join(decompiled, "AndroidManifest.xml")

    if not os.path.isfile(manifest_path):
        print("[-] AndroidManifest.xml not found in decompiled APK.")
        sys.exit(1)

    perms = parse_permissions(manifest_path)
    explain_permissions(perms)

if __name__ == "__main__":
    main()
