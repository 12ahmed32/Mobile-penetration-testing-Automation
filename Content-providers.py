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
    """Analyze AndroidManifest.xml for content providers"""
    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")
    
    print(f"Analyzing {manifest_path}...")
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    
    providers = []
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    for provider in root.findall(".//provider", ns):
        provider_info = {
            'name': provider.get(f"{{{ns['android']}}}name"),
            'exported': provider.get(f"{{{ns['android']}}}exported", "false").lower(),
            'read_permission': provider.get(f"{{{ns['android']}}}readPermission"),
            'write_permission': provider.get(f"{{{ns['android']}}}writePermission"),
            'permission': provider.get(f"{{{ns['android']}}}permission"),
            'grant_uri_permissions': provider.get(f"{{{ns['android']}}}grantUriPermissions", "false").lower(),
            'authorities': provider.get(f"{{{ns['android']}}}authorities", "").split(';'),
            'paths': []
        }
        
        # Parse path-permissions if they exist
        for path_permission in provider.findall("path-permission", ns):
            path_info = {
                'path': path_permission.get(f"{{{ns['android']}}}path"),
                'pathPrefix': path_permission.get(f"{{{ns['android']}}}pathPrefix"),
                'pathPattern': path_permission.get(f"{{{ns['android']}}}pathPattern"),
                'read_permission': path_permission.get(f"{{{ns['android']}}}readPermission"),
                'write_permission': path_permission.get(f"{{{ns['android']}}}writePermission")
            }
            provider_info['paths'].append(path_info)
        
        providers.append(provider_info)
    
    return providers

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

def generate_adb_commands(providers, package_name):
    """Generate ADB commands to interact with content providers"""
    commands = []
    
    for provider in providers:
        if provider['exported'] == "true":
            for authority in provider['authorities']:
                if not authority:
                    continue
                
                # Base content URI
                content_uri = f"content://{authority}"
                
                # Query command
                query_cmd = f"adb shell content query --uri {content_uri}"
                if provider['read_permission']:
                    query_cmd += f" --permission {provider['read_permission']}"
                commands.append(query_cmd)
                
                # Insert command (example)
                insert_cmd = f"adb shell content insert --uri {content_uri} --bind key:s:value"
                if provider['write_permission']:
                    insert_cmd += f" --permission {provider['write_permission']}"
                commands.append(insert_cmd)
                
                # Update command (example)
                update_cmd = f"adb shell content update --uri {content_uri} --bind key:s:new_value --where \"_id=1\""
                if provider['write_permission']:
                    update_cmd += f" --permission {provider['write_permission']}"
                commands.append(update_cmd)
                
                # Delete command (example)
                delete_cmd = f"adb shell content delete --uri {content_uri} --where \"_id=1\""
                if provider['write_permission']:
                    delete_cmd += f" --permission {provider['write_permission']}"
                commands.append(delete_cmd)
    
    return commands

def get_package_name(manifest_path):
    """Extract package name from manifest"""
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    return root.get("package")

def main():
    parser = ArgumentParser(description="Analyze APK for content providers")
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
        providers = analyze_manifest(manifest_path)
        
        # Step 3: Get permission details
        for provider in providers:
            permissions = set()
            if provider['read_permission']:
                permissions.add(provider['read_permission'])
            if provider['write_permission']:
                permissions.add(provider['write_permission'])
            if provider['permission']:
                permissions.add(provider['permission'])
            
            provider['permission_details'] = {}
            for perm in permissions:
                details = get_permission_details(manifest_path, perm)
                if details:
                    provider['permission_details'][perm] = details
        
        # Step 4: Generate ADB commands
        adb_commands = generate_adb_commands(providers, package_name)
        
        # Print results
        print("\n=== Content Providers ===")
        for i, provider in enumerate(providers, 1):
            print(f"\n{i}. Provider: {provider['name']}")
            print(f"   Exported: {provider['exported']}")
            print(f"   Authorities: {', '.join(provider['authorities']) or 'None'}")
            print(f"   Read Permission: {provider['read_permission'] or 'None'}")
            print(f"   Write Permission: {provider['write_permission'] or 'None'}")
            print(f"   General Permission: {provider['permission'] or 'None'}")
            print(f"   Grant URI Permissions: {provider['grant_uri_permissions']}")
            
            if provider['permission_details']:
                print("   Permission Details:")
                for perm, details in provider['permission_details'].items():
                    print(f"     - {perm}: {details['protectionLevel']}")
            
            if provider['paths']:
                print("   Path Permissions:")
                for path in provider['paths']:
                    print(f"     - Path: {path.get('path') or path.get('pathPrefix') or path.get('pathPattern')}")
                    print(f"       Read Permission: {path.get('read_permission') or 'None'}")
                    print(f"       Write Permission: {path.get('write_permission') or 'None'}")
        
        print("\n=== ADB Commands to Interact with Providers ===")
        for cmd in adb_commands:
            print(cmd)
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    main()
