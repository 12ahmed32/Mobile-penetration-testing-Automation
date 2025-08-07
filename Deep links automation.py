import os
import shutil
import subprocess
import sys
from lxml import etree
from openai import OpenAI  # New import style for v1.0.0+

# Initialize the OpenAI client
client = OpenAI(api_key="")  # Replace with your actual API key

def decompile_apk(apk_path, out_dir="decompiled_apk"):
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    print(f"[+] Decompiling APK: {apk_path}")
    try:
        subprocess.run(["apktool", "d", "-f", apk_path, "-o", out_dir], check=True)
        return os.path.join(out_dir, "AndroidManifest.xml")
    except subprocess.CalledProcessError as e:
        print("[-] Failed to decompile APK with apktool.")
        sys.exit(1)

def get_gpt_guidance(link_type, status, activity_name, scheme, host, min_sdk):
    prompt = f"""
    I'm analyzing an Android app for security vulnerabilities. Here's what I found:
    - Link Type: {link_type}
    - Status: {status}
    - Activity: {activity_name}
    - Scheme: {scheme}
    - Host: {host}
    - minSdkVersion: {min_sdk}

    Please provide:
    1. A brief explanation of the vulnerability potential
    2. Specific exploitation techniques if vulnerable
    3. Testing methodology if status is uncertain
    4. Any additional security checks I should perform
    5. Relevant tools or commands to verify the vulnerability

    Respond in clear markdown format with headings for each section.
    Keep the response concise and technical.
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a professional Android security researcher helping with vulnerability analysis."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[-] Failed to get GPT guidance: {e}")
        return "Could not retrieve GPT guidance due to an error."

def parse_manifest(manifest_path):
    with open(manifest_path, 'rb') as f:
        tree = etree.parse(f)

    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}

    # Get minSdkVersion
    min_sdk = "Not Found"
    uses_sdk = root.find('uses-sdk')
    if uses_sdk is not None:
        min_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion', 'Not Specified')

    print(f"\n[+] minSdkVersion: {min_sdk}\n")

    # Find activities with intent-filters
    for activity in root.xpath('.//activity'):
        activity_name = activity.get('{http://schemas.android.com/apk/res/android}name')
        for intent_filter in activity.findall('intent-filter'):
            categories = [c.get('{http://schemas.android.com/apk/res/android}name') for c in intent_filter.findall('category')]
            actions = [a.get('{http://schemas.android.com/apk/res/android}name') for a in intent_filter.findall('action')]
            datas = intent_filter.findall('data')
            auto_verify = intent_filter.get('autoVerify', 'false')

            if 'android.intent.category.BROWSABLE' in categories and 'android.intent.action.VIEW' in actions:
                for data in datas:
                    scheme = data.get('{http://schemas.android.com/apk/res/android}scheme', '')
                    host = data.get('{http://schemas.android.com/apk/res/android}host', '')
                    print(f"\n{'='*50}")
                    print(f"[*] Activity: {activity_name}")
                    print(f"    - Scheme: {scheme}")
                    print(f"    - Host: {host}")
                    print(f"    - autoVerify: {auto_verify}")
                    
                    # Determine link type and status
                    if scheme and not scheme.startswith('http'):
                        link_type = "Deep Link"
                        status = "✅ Hijackable"
                        print(f"    => Type: {link_type}")
                        print(f"    => Status: {status}\n")
                        guidance = get_gpt_guidance(link_type, status, activity_name, scheme, host, min_sdk)
                        print("[+] GPT Exploitation Guidance:")
                        print(guidance)
                        
                    elif scheme in ['http', 'https']:
                        if auto_verify == 'true':
                            link_type = "App Link"
                            status = "❌ Not Hijackable (if properly verified)"
                            print(f"    => Type: {link_type}")
                            print(f"    => Status: {status}\n")
                            guidance = get_gpt_guidance(link_type, status, activity_name, scheme, host, min_sdk)
                            print("[+] GPT Verification Guidance:")
                            print(guidance)
                        else:
                            if min_sdk != "Not Found" and min_sdk != "Not Specified":
                                if int(min_sdk) < 31:
                                    link_type = "Web Link"
                                    status = "✅ Hijackable (supports Android < 12)"
                                    print(f"    => Type: {link_type}")
                                    print(f"    => Status: {status}\n")
                                    guidance = get_gpt_guidance(link_type, status, activity_name, scheme, host, min_sdk)
                                    print("[+] GPT Exploitation Guidance:")
                                    print(guidance)
                                else:
                                    link_type = "Web Link"
                                    status = "❌ Not Hijackable (minSdk >= 31)"
                                    print(f"    => Type: {link_type}")
                                    print(f"    => Status: {status}\n")
                                    guidance = get_gpt_guidance(link_type, status, activity_name, scheme, host, min_sdk)
                                    print("[+] GPT Verification Guidance:")
                                    print(guidance)
                            else:
                                link_type = "Web Link"
                                status = "⚠️ Unknown hijackability (minSdk missing)"
                                print(f"    => Type: {link_type}")
                                print(f"    => Status: {status}\n")
                                guidance = get_gpt_guidance(link_type, status, activity_name, scheme, host, min_sdk)
                                print("[+] GPT Testing Guidance:")
                                print(guidance)

def main():
    if len(sys.argv) != 2:
        print("Usage: python deep_link_checker.py <target.apk>")
        sys.exit(1)

    apk_path = sys.argv[1]
    manifest_path = decompile_apk(apk_path)
    parse_manifest(manifest_path)

if __name__ == "__main__":
    main()
