import os
import json
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import re
from argparse import ArgumentParser
from colorama import Fore, Style, init
from pathlib import Path

# Enable colored output
init(autoreset=True)

ns = {"android": "http://schemas.android.com/apk/res/android"}
get = lambda el, name, default=None: el.get(f"{{{ns['android']}}}{name}", default)


# ----------------- APKTOOL -----------------

def decompile_apk(apk_path, output_dir):
    """Decompile APK using apktool."""
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    print(f"{Fore.CYAN}[+] Decompiling APK...{Style.RESET_ALL}")

    result = subprocess.run(
        ["apktool", "d", apk_path, "-o", output_dir, "-f"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"{Fore.RED}[-] Apktool failed:{Style.RESET_ALL}\n{result.stderr}")
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Decompilation complete{Style.RESET_ALL}")
    return True


# ----------------- WEBVIEW ANALYSIS -----------------

def find_smali_files(decompiled_dir):
    """Find all smali files in the decompiled directory."""
    smali_files = []
    for root, dirs, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith('.smali'):
                smali_files.append(os.path.join(root, file))
    return smali_files


def analyze_webview_in_smali(smali_file):
    """Analyze a smali file for WebView usage and security issues."""
    vulnerabilities = []
    
    try:
        with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Check if file contains WebView
        if 'Landroid/webkit/WebView;' not in content:
            return None
            
        webview_info = {
            'file': smali_file,
            'uses_webview': True,
            'vulnerabilities': []
        }
        
        # Check for JavaScript enabled
        if re.search(r'invoke-virtual.*WebSettings;->setJavaScriptEnabled\(Z\)V', content):
            # Try to determine if it's set to true (const/4 v\d+, 0x1 or similar)
            js_pattern = re.search(
                r'const/4\s+v(\d+),\s*0x1.*?invoke-virtual.*v\1.*setJavaScriptEnabled',
                content,
                re.DOTALL
            )
            if js_pattern or 'setJavaScriptEnabled' in content:
                webview_info['javascript_enabled'] = True
                webview_info['vulnerabilities'].append({
                    'type': 'JavaScript Enabled',
                    'severity': 'MEDIUM',
                    'description': 'JavaScript is enabled in WebView, increasing attack surface'
                })
        
        # Check for File Access enabled
        if 'setAllowFileAccess' in content:
            webview_info['file_access_enabled'] = True
            webview_info['vulnerabilities'].append({
                'type': 'File Access Enabled',
                'severity': 'HIGH',
                'description': 'File access is enabled, may allow access to local files'
            })
        
        # Check for Universal Access from File URLs
        if 'setAllowUniversalAccessFromFileURLs' in content:
            webview_info['universal_access_from_file'] = True
            webview_info['vulnerabilities'].append({
                'type': 'Universal Access From File URLs',
                'severity': 'CRITICAL',
                'description': 'Allows universal access from file URLs, major security risk'
            })
        
        # Check for File Access from File URLs
        if 'setAllowFileAccessFromFileURLs' in content:
            webview_info['file_access_from_file'] = True
            webview_info['vulnerabilities'].append({
                'type': 'File Access From File URLs',
                'severity': 'HIGH',
                'description': 'Allows file access from file URLs'
            })
        
        # Check for JavaScript Interface (addJavascriptInterface)
        if 'addJavascriptInterface' in content:
            webview_info['has_javascript_interface'] = True
            webview_info['vulnerabilities'].append({
                'type': 'JavaScript Interface Exposed',
                'severity': 'CRITICAL',
                'description': 'Native methods exposed to JavaScript, potential RCE if not properly secured'
            })
        
        # Check for loadUrl with intent data
        if re.search(r'loadUrl|loadData|loadDataWithBaseURL', content):
            if re.search(r'getIntent|getStringExtra|getDataString', content):
                webview_info['loads_intent_data'] = True
                webview_info['vulnerabilities'].append({
                    'type': 'Intent Data Loaded in WebView',
                    'severity': 'CRITICAL',
                    'description': 'WebView loads URL/data from Intent, vulnerable to intent redirection/XSS'
                })
        
        # Check for SSL Error Handler bypass
        if 'onReceivedSslError' in content and 'proceed' in content:
            webview_info['ssl_error_bypass'] = True
            webview_info['vulnerabilities'].append({
                'type': 'SSL Error Handler Bypass',
                'severity': 'HIGH',
                'description': 'SSL certificate validation may be bypassed'
            })
        
        # Check for mixed content mode
        if 'setMixedContentMode' in content:
            webview_info['mixed_content_mode_set'] = True
            webview_info['vulnerabilities'].append({
                'type': 'Mixed Content Mode Modified',
                'severity': 'MEDIUM',
                'description': 'Mixed content mode is modified, may allow insecure content'
            })
        
        # Check for WebViewClient with shouldOverrideUrlLoading
        if 'shouldOverrideUrlLoading' in content:
            webview_info['custom_url_handling'] = True
            # Check if it handles intent:// URLs
            if re.search(r'intent://|Intent\.parseUri', content):
                webview_info['vulnerabilities'].append({
                    'type': 'Intent URL Scheme Handler',
                    'severity': 'HIGH',
                    'description': 'Handles intent:// URLs, may be vulnerable to intent injection'
                })
        
        return webview_info if webview_info['vulnerabilities'] else None
        
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error analyzing {smali_file}: {e}{Style.RESET_ALL}")
        return None


def analyze_activity_intent_redirection(smali_file):
    """Check if an activity is vulnerable to intent redirection."""
    vulnerabilities = []
    
    try:
        with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Check for common intent redirection patterns
        patterns = [
            # Starting activity from intent data
            (r'getIntent.*?getParcelableExtra.*?startActivity', 
             'Intent Redirection via Parcelable Extra',
             'Activity launches another activity from parcelable intent extra'),
            
            # Starting activity from serializable extra
            (r'getIntent.*?getSerializableExtra.*?startActivity',
             'Intent Redirection via Serializable Extra',
             'Activity launches another activity from serializable intent extra'),
            
            # Direct intent forwarding
            (r'getIntent.*?startActivity\(v\d+\)',
             'Direct Intent Forwarding',
             'Activity directly forwards received intent to another component'),
            
            # Intent with extras forwarding
            (r'getIntent.*?getExtras.*?startActivity',
             'Intent with Extras Forwarding',
             'Activity forwards intent extras to another activity'),
        ]
        
        for pattern, vuln_type, description in patterns:
            if re.search(pattern, content, re.DOTALL):
                vulnerabilities.append({
                    'type': vuln_type,
                    'severity': 'HIGH',
                    'description': description,
                    'file': smali_file
                })
        
        return vulnerabilities
        
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error analyzing intent redirection in {smali_file}: {e}{Style.RESET_ALL}")
        return []


def analyze_webview_vulnerabilities(decompiled_dir, activity_list):
    """Comprehensive WebView vulnerability analysis."""
    print(f"\n{Fore.CYAN}[+] Analyzing WebView vulnerabilities...{Style.RESET_ALL}")
    
    webview_results = []
    smali_files = find_smali_files(decompiled_dir)
    
    print(f"{Fore.CYAN}[+] Found {len(smali_files)} smali files to analyze{Style.RESET_ALL}")
    
    for smali_file in smali_files:
        result = analyze_webview_in_smali(smali_file)
        if result:
            # Try to match with activity name
            activity_name = None
            for activity in activity_list:
                # Convert activity name to smali path format
                smali_path = activity['name'].replace('.', '/') + '.smali'
                if smali_path in smali_file:
                    activity_name = activity['name']
                    result['activity'] = activity_name
                    result['exported'] = activity['exported']
                    break
            
            webview_results.append(result)
    
    return webview_results


def analyze_intent_redirection_vulnerabilities(decompiled_dir, activity_list):
    """Analyze activities for intent redirection vulnerabilities."""
    print(f"\n{Fore.CYAN}[+] Analyzing intent redirection vulnerabilities...{Style.RESET_ALL}")
    
    intent_redirection_results = []
    
    for activity in activity_list:
        if not activity['exported']:
            continue
            
        # Convert activity name to smali file path
        smali_path = activity['name'].replace('.', '/')
        
        # Search for the smali file
        for root, dirs, files in os.walk(decompiled_dir):
            for file in files:
                if file.endswith('.smali') and smali_path in os.path.join(root, file):
                    full_path = os.path.join(root, file)
                    vulnerabilities = analyze_activity_intent_redirection(full_path)
                    
                    if vulnerabilities:
                        intent_redirection_results.append({
                            'activity': activity['name'],
                            'exported': activity['exported'],
                            'permission': activity['permission'],
                            'vulnerabilities': vulnerabilities
                        })
                    break
    
    return intent_redirection_results


# ----------------- DEEP LINK ANALYSIS -----------------

def analyze_deeplinks(root):
    """Analyze deep links and app links from AndroidManifest.xml."""
    report = []

    uses_sdk = root.find("uses-sdk")
    min_sdk = "Unknown"
    if uses_sdk is not None:
        min_sdk = uses_sdk.get(f"{{{ns['android']}}}minSdkVersion", "Not Specified")

    print(f"\n{Fore.YELLOW}[+] minSdkVersion: {min_sdk}{Style.RESET_ALL}")

    for a in root.findall(".//activity"):
        name = get(a, "name")
        exported = get(a, "exported", "false").lower()

        for f in a.findall("intent-filter"):
            actions = [get(x, "name") for x in f.findall("action")]
            categories = [get(x, "name") for x in f.findall("category")]
            auto = f.get("autoVerify", "false").lower()

            if "android.intent.action.VIEW" not in actions:
                continue
            if "android.intent.category.BROWSABLE" not in categories:
                continue

            datas = f.findall("data")
            schemes = set()
            hosts = set()

            for d in datas:
                s = d.get(f"{{{ns['android']}}}scheme")
                h = d.get(f"{{{ns['android']}}}host")
                if s:
                    schemes.add(s)
                if h:
                    hosts.add(h)

            if not schemes:
                schemes.add("")
            if not hosts:
                hosts.add("")

            for s in schemes:
                for h in hosts:
                    print("\n" + "="*60)
                    print(f"{Fore.CYAN}[*] Activity: {name}{Style.RESET_ALL}")
                    print(f"    Exported: {exported}")
                    print(f"    Scheme: {s}")
                    print(f"    Host: {h}")
                    print(f"    autoVerify: {auto}")

                    entry = {
                        "activity": name,
                        "scheme": s,
                        "host": h,
                        "exported": exported,
                        "autoVerify": auto,
                        "minSdkVersion": min_sdk
                    }

                    if s and not s.startswith("http"):
                        link_type = "Deep Link"
                        if exported == "true":
                            status = "Hijackable"
                            color = Fore.GREEN
                        else:
                            status = "Not Hijackable (not exported)"
                            color = Fore.RED

                    elif s in ["http", "https"]:
                        link_type = "Web Link / App Link"

                        if auto == "true":
                            status = "Not Hijackable (App Link)"
                            color = Fore.RED
                        else:
                            try:
                                if min_sdk not in ["Unknown", "Not Specified"] and int(min_sdk) < 31:
                                    status = "Hijackable (Android < 12)"
                                    color = Fore.GREEN
                                else:
                                    status = "Not Hijackable"
                                    color = Fore.RED
                            except:
                                status = "Unknown"
                                color = Fore.YELLOW
                    else:
                        link_type = "Unknown"
                        status = "Unknown"
                        color = Fore.YELLOW

                    print(f"    Type: {link_type}")
                    print(f"    Status: {color}{status}{Style.RESET_ALL}")

                    entry["type"] = link_type
                    entry["status"] = status
                    report.append(entry)

    return report


# ----------------- EXPORTED ACTIVITIES ANALYSIS -----------------

def analyze_exported_activities(root):
    """Parse AndroidManifest.xml for exported activities and permissions."""
    package_name = root.get('package')
    permissions = {}
    activities = []

    # Extract declared permissions
    for perm in root.findall("uses-permission"):
        perm_name = get(perm, "name")
        if perm_name:
            permissions[perm_name] = "normal"  # Default level (can be refined)

    # Extract activities and their properties
    for activity in root.findall(".//activity"):
        activity_name = get(activity, "name")
        exported = get(activity, "exported", "false").lower() == "true"
        permission = get(activity, "permission")

        # Check intent-filter (implicit export)
        intent_filters = activity.findall("intent-filter")
        has_intent_filters = len(intent_filters) > 0

        # If 'exported' is not explicitly set, intent-filters make it exported by default
        final_exported = exported or (has_intent_filters and "exported" not in activity.attrib)

        # Get protection level for the permission
        protection_level = permissions.get(permission, "none")
        
        # Check for signature-based protection
        is_signature_protected = "signature" in protection_level.lower() if protection_level != "none" else False

        activities.append({
            "name": activity_name,
            "exported": final_exported,
            "permission": permission,
            "protection_level": protection_level,
            "signature_protected": is_signature_protected,
            "vulnerable": final_exported and (not permission or not is_signature_protected)
        })

    return {
        "package": package_name,
        "activities": activities,
        "permissions": permissions
    }


def generate_adb_command(package, activity):
    """Generate ADB command to launch an activity."""
    return f"adb shell am start -n {package}/{activity}"


# ----------------- RECEIVERS -----------------

def analyze_receivers(root):
    """Analyze broadcast receivers."""
    res = []
    for r in root.findall(".//receiver"):
        exported = get(r, "exported", "false").lower()
        actions = [get(a, "name") for f in r.findall("intent-filter") for a in f.findall("action")]
        permission = get(r, "permission")

        res.append({
            "receiver": get(r, "name"),
            "exported": exported,
            "permission": permission,
            "actions": actions,
            "status": "Exposed" if exported == "true" else "Internal"
        })

    return res


# ----------------- PROVIDERS -----------------

def analyze_providers(root):
    """Analyze content providers."""
    res = []
    for p in root.findall(".//provider"):
        exported = get(p, "exported", "false").lower()
        permission = get(p, "permission")
        read_permission = get(p, "readPermission")
        write_permission = get(p, "writePermission")
        
        res.append({
            "provider": get(p, "name"),
            "exported": exported,
            "permission": permission,
            "authorities": (get(p, "authorities") or "").split(";"),
            "read_permission": read_permission,
            "write_permission": write_permission,
            "status": "Exposed" if exported == "true" else "Internal"
        })
    return res


# ----------------- SERVICES -----------------

def analyze_services(root):
    """Analyze services."""
    res = []
    for s in root.findall(".//service"):
        exported = get(s, "exported", "false").lower()
        permission = get(s, "permission")
        actions = [get(a, "name") for f in s.findall("intent-filter") for a in f.findall("action")]

        res.append({
            "service": get(s, "name"),
            "exported": exported,
            "permission": permission,
            "actions": actions,
            "status": "Exposed" if exported == "true" else "Internal"
        })
    return res


# ----------------- REPORT GENERATION -----------------

def print_webview_report(webview_results):
    """Print WebView vulnerability report."""
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{'WEBVIEW VULNERABILITY ANALYSIS':^60}")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    if not webview_results:
        print(f"{Fore.GREEN}[+] No WebView vulnerabilities detected{Style.RESET_ALL}")
        return
    
    for result in webview_results:
        activity_name = result.get('activity', 'Unknown Activity')
        exported = result.get('exported', False)
        
        severity_color = Fore.RED if exported else Fore.YELLOW
        export_status = "EXPORTED" if exported else "NOT EXPORTED"
        
        print(f"\n{severity_color}[{export_status}] {activity_name}{Style.RESET_ALL}")
        print(f"    File: {os.path.basename(result['file'])}")
        
        for vuln in result['vulnerabilities']:
            severity_colors = {
                'CRITICAL': Fore.RED,
                'HIGH': Fore.MAGENTA,
                'MEDIUM': Fore.YELLOW,
                'LOW': Fore.CYAN
            }
            color = severity_colors.get(vuln['severity'], Fore.WHITE)
            
            print(f"    {color}[{vuln['severity']}] {vuln['type']}{Style.RESET_ALL}")
            print(f"        → {vuln['description']}")


def print_intent_redirection_report(intent_results):
    """Print intent redirection vulnerability report."""
    print(f"\n{Fore.RED}{'='*60}")
    print(f"{'INTENT REDIRECTION VULNERABILITIES':^60}")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    if not intent_results:
        print(f"{Fore.GREEN}[+] No intent redirection vulnerabilities detected{Style.RESET_ALL}")
        return
    
    for result in intent_results:
        print(f"\n{Fore.RED}[VULNERABLE] {result['activity']}{Style.RESET_ALL}")
        print(f"    Exported: {result['exported']}")
        print(f"    Permission: {result['permission'] or 'None'}")
        
        for vuln in result['vulnerabilities']:
            print(f"    {Fore.RED}[{vuln['severity']}] {vuln['type']}{Style.RESET_ALL}")
            print(f"        → {vuln['description']}")


# ----------------- MAIN -----------------

def main():
    parser = ArgumentParser(description="Comprehensive Android APK Security Analysis Tool with WebView Detection")
    parser.add_argument("apk", help="Path to APK file")
    parser.add_argument("-o", "--out", default="android_attack_surface.json", 
                       help="Output JSON file (default: android_attack_surface.json)")
    parser.add_argument("-k", "--keep", action="store_true",
                       help="Keep decompiled source directory")
    parser.add_argument("-c", "--commands", action="store_true",
                       help="Generate ADB commands for vulnerable activities")
    parser.add_argument("-w", "--webview", action="store_true",
                       help="Perform deep WebView vulnerability analysis (slower)")
    args = parser.parse_args()

    if not os.path.exists(args.apk):
        print(f"{Fore.RED}[-] APK file not found: {args.apk}{Style.RESET_ALL}")
        sys.exit(1)

    # Create output directory
    if args.keep:
        outdir = args.apk + "_src"
    else:
        temp_dir = tempfile.mkdtemp(prefix="apk_analysis_")
        outdir = temp_dir

    # Decompile APK
    if not decompile_apk(args.apk, outdir):
        sys.exit(1)

    manifest = os.path.join(outdir, "AndroidManifest.xml")
    if not os.path.exists(manifest):
        print(f"{Fore.RED}[-] Manifest not found: {manifest}{Style.RESET_ALL}")
        sys.exit(1)

    root = ET.parse(manifest).getroot()

    # Run all analyses
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{'ANDROID APK SECURITY ANALYSIS':^60}")
    print(f"{'='*60}{Style.RESET_ALL}")

    # Package info
    package_info = analyze_exported_activities(root)
    print(f"\n{Fore.YELLOW}[+] Package Name: {package_info['package']}{Style.RESET_ALL}")

    # Deep link analysis
    deep = analyze_deeplinks(root)
    
    # WebView and Intent Redirection Analysis
    webview_results = []
    intent_redirection_results = []
    
    if args.webview:
        webview_results = analyze_webview_vulnerabilities(outdir, package_info['activities'])
        intent_redirection_results = analyze_intent_redirection_vulnerabilities(
            outdir, package_info['activities']
        )
    
    # Exported activities analysis
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"{'EXPORTED ACTIVITIES ANALYSIS':^60}")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    vulnerable_activities = []
    for activity in package_info["activities"]:
        color = Fore.RED if activity["vulnerable"] else Fore.GREEN
        status = "VULNERABLE" if activity["vulnerable"] else "SAFE"
        
        print(f"\n{color}[{status}] {activity['name']}{Style.RESET_ALL}")
        print(f"    - Exported: {activity['exported']}")
        print(f"    - Permission: {activity['permission'] or 'None'}")
        print(f"    - Protection Level: {activity['protection_level']}")
        print(f"    - Signature Protected: {activity['signature_protected']}")
        
        if activity["vulnerable"]:
            vulnerable_activities.append(activity)
            if args.commands:
                cmd = generate_adb_command(package_info["package"], activity["name"])
                print(f"    - {Fore.CYAN}[!] ADB Command: {cmd}{Style.RESET_ALL}")

    # Print WebView report
    if args.webview:
        print_webview_report(webview_results)
        print_intent_redirection_report(intent_redirection_results)

    # Broadcast receivers
    recv = analyze_receivers(root)
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"{'BROADCAST RECEIVERS':^60}")
    print(f"{'='*60}{Style.RESET_ALL}")
    for r in recv:
        color = Fore.RED if r["status"] == "Exposed" else Fore.GREEN
        print(f"\n{color}[{r['status']}] {r['receiver']}{Style.RESET_ALL}")
        if r["permission"]:
            print(f"    - Permission: {r['permission']}")
        for a in r['actions']:
            print(f"    - Action: {a}")

    # Content providers
    prov = analyze_providers(root)
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{'CONTENT PROVIDERS':^60}")
    print(f"{'='*60}{Style.RESET_ALL}")
    for p in prov:
        color = Fore.RED if p["status"] == "Exposed" else Fore.GREEN
        print(f"\n{color}[{p['status']}] {p['provider']}{Style.RESET_ALL}")
        if p["authorities"] and p["authorities"][0]:
            print(f"    - Authorities: {', '.join(p['authorities'])}")
        if p["permission"]:
            print(f"    - Permission: {p['permission']}")
        if p["read_permission"]:
            print(f"    - Read Permission: {p['read_permission']}")
        if p["write_permission"]:
            print(f"    - Write Permission: {p['write_permission']}")

    # Services
    services = analyze_services(root)
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{'SERVICES':^60}")
    print(f"{'='*60}{Style.RESET_ALL}")
    for s in services:
        color = Fore.RED if s["status"] == "Exposed" else Fore.GREEN
        print(f"\n{color}[{s['status']}] {s['service']}{Style.RESET_ALL}")
        if s["permission"]:
            print(f"    - Permission: {s['permission']}")
        for a in s['actions']:
            print(f"    - Action: {a}")

    # Summary
    print(f"\n{Fore.YELLOW}{'='*60}")
    print(f"{'SUMMARY':^60}")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"Total Activities: {len(package_info['activities'])}")
    print(f"Exported Activities: {len([a for a in package_info['activities'] if a['exported']])}")
    print(f"Vulnerable Activities: {len(vulnerable_activities)}")
    print(f"Deep Links Found: {len(deep)}")
    print(f"Broadcast Receivers: {len(recv)}")
    print(f"Content Providers: {len(prov)}")
    print(f"Services: {len(services)}")
    
    if args.webview:
        print(f"WebView Vulnerabilities: {len(webview_results)}")
        print(f"Intent Redirection Issues: {len(intent_redirection_results)}")

    # Save results to JSON
    results = {
        "package_info": package_info,
        "deep_links": deep,
        "broadcast_receivers": recv,
        "content_providers": prov,
        "services": services,
        "vulnerable_activities": vulnerable_activities,
        "adb_commands": [generate_adb_command(package_info["package"], a["name"]) 
                        for a in vulnerable_activities] if args.commands else []
    }
    
    if args.webview:
        results["webview_vulnerabilities"] = webview_results
        results["intent_redirection_vulnerabilities"] = intent_redirection_results

    with open(args.out, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n{Fore.CYAN}[+] JSON report saved → {args.out}{Style.RESET_ALL}")

    # Cleanup
    if not args.keep and os.path.exists(outdir):
        shutil.rmtree(outdir)
        print(f"{Fore.GREEN}[+] Temporary directory cleaned{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
