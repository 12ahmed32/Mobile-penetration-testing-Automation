import os
import subprocess
import xml.etree.ElementTree as ET
from argparse import ArgumentParser

def decompile_apk(apk_path, output_dir):
    """Decompile APK using apktool"""
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    
    print(f"Decompiling {apk_path}...")
    result = subprocess.run(["apktool", "d", apk_path, "-o", output_dir, "-f"], 
                           capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Apktool failed: {result.stderr}")
    print("Decompilation completed successfully.")

def analyze_manifest(manifest_path):
    """Analyze AndroidManifest.xml for exported broadcast receivers"""
    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")
    
    print(f"Analyzing {manifest_path}...")
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    
    receivers = []
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    for receiver in root.findall(".//receiver", ns):
        exported = receiver.get(f"{{{ns['android']}}}exported", "false").lower()
        if exported == "true":
            receiver_info = {
                'name': receiver.get(f"{{{ns['android']}}}name"),
                'permission': receiver.get(f"{{{ns['android']}}}permission"),
                'actions': []
            }
            
            # Get intent filters
            for intent_filter in receiver.findall("intent-filter", ns):
                for action in intent_filter.findall("action", ns):
                    action_name = action.get(f"{{{ns['android']}}}name")
                    if action_name:
                        receiver_info['actions'].append(action_name)
            
            receivers.append(receiver_info)
    
    return receivers

def get_permission_details(manifest_path, permission_name):
    """Get protection level for a permission from manifest"""
    if not permission_name:
        return None
    
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    for permission in root.findall(".//permission", ns):
        if permission.get(f"{{{ns['android']}}}name") == permission_name:
            return {
                'protectionLevel': permission.get(f"{{{ns['android']}}}protectionLevel", "normal")
            }
    return None

def generate_adb_commands(receivers, package_name):
    """Generate ADB commands to invoke broadcast receivers"""
    commands = []
    for receiver in receivers:
        receiver_name = receiver['name']
        permission = receiver['permission']
        
        if receiver['actions']:
            for action in receiver['actions']:
                cmd = f"adb shell am broadcast -a {action}"
                if permission:
                    cmd += f" --permission {permission}"
                cmd += f" -n {package_name}/{receiver_name}"
                commands.append(cmd)
        else:
            cmd = f"adb shell am broadcast -n {package_name}/{receiver_name}"
            if permission:
                cmd += f" --permission {permission}"
            commands.append(cmd)
    
    return commands

def get_package_name(manifest_path):
    """Extract package name from manifest"""
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    return root.get("package")

def main():
    parser = ArgumentParser(description="Analyze APK for exported broadcast receivers")
    parser.add_argument("apk_file", help="Path to the APK file")
    args = parser.parse_args()
    
    apk_path = os.path.abspath(args.apk_file)
    output_dir = os.path.splitext(apk_path)[0] + "_decompiled"
    
    try:
        # Step 1: Decompile APK
        decompile_apk(apk_path, output_dir)
        
        # Step 2: Analyze manifest
        manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
        package_name = get_package_name(manifest_path)
        receivers = analyze_manifest(manifest_path)
        
        # Step 3: Get permission details
        for receiver in receivers:
            if receiver['permission']:
                perm_details = get_permission_details(manifest_path, receiver['permission'])
                if perm_details:
                    receiver['permission_details'] = perm_details
        
        # Step 4: Generate ADB commands
        adb_commands = generate_adb_commands(receivers, package_name)
        
        # Print results
        print("\n=== Exported Broadcast Receivers ===")
        for i, receiver in enumerate(receivers, 1):
            print(f"\n{i}. Receiver: {receiver['name']}")
            print(f"   Permission: {receiver['permission'] or 'None'}")
            if receiver.get('permission_details'):
                print(f"   Protection Level: {receiver['permission_details']['protectionLevel']}")
            if receiver['actions']:
                print("   Actions:")
                for action in receiver['actions']:
                    print(f"     - {action}")
            else:
                print("   No intent filters (must be called explicitly)")
        
        print("\n=== ADB Commands to Invoke Receivers ===")
        for cmd in adb_commands:
            print(cmd)
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    main()
