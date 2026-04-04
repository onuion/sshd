#!/usr/bin/env python3
import argparse
import sys
import subprocess
import os
import re

CONFIG_FILE = "/opt/onuion-sshd/config.py"
SERVICE_NAME = "onuion-agent"

# If we are running in the local directory (for development)
if not os.path.exists(CONFIG_FILE):
    CONFIG_FILE = "config.py"

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError:
        # Error message will be printed by systemctl
        pass

def update_config(key, value):
    if not os.path.exists(CONFIG_FILE):
        print(f"❌ Error: {CONFIG_FILE} not found.")
        return

    with open(CONFIG_FILE, 'r') as f:
        content = f.read()

    # Find and replace KEY = VALUE structure using regex
    pattern = rf"^({key}\s*=\s*)(.*)$"
    
    # Formatting based on value type (bool, int, or string)
    if value.lower() == 'true':
        formatted_value = 'True'
    elif value.lower() == 'false':
        formatted_value = 'False'
    elif value.isdigit():
        formatted_value = value
    else:
        # Add quotes if it's a string
        formatted_value = f'"{value}"' if not (value.startswith('"') or value.startswith("'")) else value

    if re.search(pattern, content, re.MULTILINE):
        new_content = re.sub(pattern, f"{key} = {formatted_value}", content, flags=re.MULTILINE)
        with open(CONFIG_FILE, 'w') as f:
            f.write(new_content)
        print(f"✅ Success: {key} value updated to {formatted_value}.")
        print(f"🔄 Remember to run 'osshd restart' to apply changes.")
    else:
        print(f"❌ Error: Key '{key}' not found in {CONFIG_FILE}.")

def main():
    parser = argparse.ArgumentParser(description="Onuion SSHD (osshd) Agent Control Panel")
    subparsers = parser.add_subparsers(dest="command")

    # Core commands
    subparsers.add_parser("start", help="Starts the service")
    subparsers.add_parser("stop", help="Stops the service")
    subparsers.add_parser("restart", help="Restarts the service")
    subparsers.add_parser("status", help="Shows service status")
    
    # Configuration commands
    config_parser = subparsers.add_parser("config", help="Manages configuration")
    config_parser.add_argument("--set", metavar="KEY=VALUE", help="Updates value (e.g., --set BLOCK_THRESHOLD=90)")
    config_parser.add_argument("--list", action="store_true", help="Lists current settings")

    # Default to 'start' if no arguments provided
    if len(sys.argv) == 1:
        sys.argv.append("start")

    args = parser.parse_args()

    if args.command == "start":
        print(f"🚀 Starting osshd (Agent)...")
        run_cmd(f"sudo systemctl start {SERVICE_NAME}")

    elif args.command == "stop":
        print(f"🛑 Stopping osshd (Agent)...")
        run_cmd(f"sudo systemctl stop {SERVICE_NAME}")

    elif args.command == "restart":
        print(f"🔄 Restarting osshd (Agent)...")
        run_cmd(f"sudo systemctl restart {SERVICE_NAME}")

    elif args.command == "status":
        run_cmd(f"sudo systemctl status {SERVICE_NAME}")

    elif args.command == "config":
        if args.set:
            if '=' in args.set:
                k, v = args.set.split('=', 1)
                update_config(k.strip(), v.strip())
            else:
                print("⚠️ Usage: osshd config --set KEY=VALUE")
        elif args.list:
            print(f"📑 {CONFIG_FILE} contents:\n")
            with open(CONFIG_FILE, 'r') as f:
                print(f.read())

if __name__ == "__main__":
    main()

