import sys
import os
import subprocess
import json

# Add project dir to path for imports
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(PROJECT_DIR)

try:
    from enforcer import is_valid_ip
except ImportError as e:
    print(f"Could not import enforcer: {e}")
    sys.exit(1)

def test_ip_validation():
    print("Testing IP validation...")
    valid_ips = ["127.0.0.1", "192.168.1.1", "::1", "2001:db8::1", "8.8.8.8"]
    invalid_ips = ["127.0.0.1; rm -rf /", "not-an-ip", "1.2.3.4.5", "  127.0.0.1  ", "127.0.0.1\nrm"]
    
    for ip in valid_ips:
        if not is_valid_ip(ip):
            print(f"❌ Failed: {ip} should be valid")
            sys.exit(1)
        else:
            print(f"  - {ip} (VALID)")
    
    for ip in invalid_ips:
        if is_valid_ip(ip):
            print(f"❌ Failed: {ip} should be invalid")
            sys.exit(1)
        else:
            print(f"  - {ip} (INVALID)")
    print("✅ IP validation passed.")

def test_pam_fail_closed():
    print("Testing PAM fail-closed...")
    # Ensure socket path doesn't exist or is different to trigger exception
    env = os.environ.copy()
    env["PAM_USER"] = "testuser"
    env["PAM_RHOST"] = "1.2.3.4"
    env["PAM_TYPE"] = "auth"
    
    # Run the script and expect exit code 1
    try:
        # We need to make sure it doesn't accidentally connect to a real socket if it exists
        # In a test environment, /var/run/onuion-sshd.sock likely doesn't exist or we can't access it.
        result = subprocess.run(
            [sys.executable, os.path.join(PROJECT_DIR, "pam_onuion_check.py")],
            env=env,
            capture_output=True,
            text=True
        )
        print(f"  - Return code: {result.returncode}")
        print(f"  - Stderr: {result.stderr.strip()}")
        if result.returncode == 1:
            print("✅ PAM fail-closed passed (exited with 1 on error).")
        else:
            print(f"❌ PAM fail-closed failed (exited with {result.returncode}).")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Error running PAM check: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_ip_validation()
    test_pam_fail_closed()
