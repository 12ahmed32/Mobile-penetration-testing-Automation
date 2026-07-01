import os
import subprocess
import sys
import xml.etree.ElementTree as ET

BANNER = """
===========================================
   Android APK → Frida Hook Automation
===========================================
"""

def run_cmd(cmd, shell=False, timeout=60):
    print(f"[+] Running: {cmd}")
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        if result.stdout.strip():
            print(result.stdout)
        if result.stderr.strip():
            print("STDERR:", result.stderr)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"[-] Command timed out after {timeout} seconds: {cmd}")
        return None
    except Exception as e:
        print(f"[-] Error running command: {e}")
        return None


def decompile_apk(apk_path):
    print("[+] Decompiling APK with apktool...")
    output_dir = apk_path.replace(".apk", "_dec")

    apktool_commands = [
        ["apktool", "d", apk_path, "-f", "-o", output_dir],
        ["apktool.bat", "d", apk_path, "-f", "-o", output_dir],
    ]

    for cmd in apktool_commands:
        try:
            output = run_cmd(cmd, timeout=150)
            if output is not None:
                print("[+] Decompilation complete:", output_dir)
                return output_dir
        except FileNotFoundError:
            continue

    print("[-] Could not decompile APK with apktool.")
    if os.path.exists(output_dir):
        print(f"[!] Output directory exists: {output_dir}")
        return output_dir

    sys.exit(1)


def extract_library_name(decompiled_dir):
    print("[+] Searching for native libraries in /lib...")
    lib_dir = os.path.join(decompiled_dir, "lib")

    if not os.path.exists(lib_dir):
        print("[-] No /lib directory found in APK.")
        return None

    for root, dirs, files in os.walk(lib_dir):
        for f in files:
            if f.endswith(".so"):
                print("[+] Found native library:", f)
                return f

    print("[-] No .so library found.")
    return None


def extract_package_name(decompiled_dir):
    print("[+] Extracting package name from AndroidManifest.xml...")
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")

    if not os.path.exists(manifest_path):
        print("[-] AndroidManifest.xml not found!")
        return None

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        package_name = root.attrib.get("package", None)
        print("[+] Package name:", package_name)
        return package_name
    except Exception as e:
        print(f"[-] Error parsing AndroidManifest.xml: {e}")
        return None


def generate_frida_script(library_name):
    print("[+] Generating Frida script...")

    script = f"""
var exports = Process.getModuleByName("{library_name}").enumerateExports();

exports.forEach(function(element) {{
    console.log("[EXPORT] " + element.name);
    console.log("[ADDRESS] " + element.address);
}});
    """

    # Escape single quotes for safe --eval execution
    script = script.replace("'", "\\'")
    return script


def main():
    print(BANNER)

    if len(sys.argv) < 2:
        print("Usage: python auto_frida.py file.apk")
        sys.exit(1)

    apk = sys.argv[1]

    if not os.path.exists(apk):
        print("[-] APK not found!")
        sys.exit(1)

    dec_dir = decompile_apk(apk)
    if not dec_dir:
        sys.exit(1)

    lib_name = extract_library_name(dec_dir)
    if not lib_name:
        print("[-] No native library found. Exiting.")
        sys.exit(1)

    pkg = extract_package_name(dec_dir)
    if not pkg:
        print("[-] Could not extract package name. Exiting.")
        sys.exit(1)

    script = generate_frida_script(lib_name)

    print("\nChoose Frida mode:")
    print("1) Hook already running process")
    print("2) Spawn app with Frida")

    choice = input("Enter choice (1/2): ")

    if choice == "1":
       print("[+] Listing running apps...")
       output = run_cmd(["frida-ps", "-Uai"])

    # Extract PID of the package
       pid = None
       for line in output.splitlines():
          if pkg in line:
              parts = line.split()
              pid = parts[0]
              break

       if pid is None:
          print("[-] Could not find PID for package. Is the app running?")
          sys.exit(1)

       print(f"[+] Attaching to {pkg} (PID {pid}) ...")
       cmd = f"frida -U -p {pid} --eval '{script}'"
       os.system(cmd)

    elif choice == "2":
        print(f"[+] Spawning {pkg} with Frida...")
        cmd = f"frida -U -f {pkg} --eval '{script}'"
        os.system(cmd)

    else:
        print("[-] Invalid choice. Exiting.")


if __name__ == "__main__":
    main()
