import shlex
import threading
import time
import subprocess
import ipaddress
from config import ENABLE_IP_BLOCK, BLOCK_COMMAND, UNBLOCK_COMMAND, DEFAULT_BLOCK_DURATION

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def unblock_ip_later(ip: str, duration: int):
    if not is_valid_ip(ip):
        print(f"[ERROR] Invalid ip address for unblocking: {ip}", flush=True)
        return

    time.sleep(duration)
    cmd = UNBLOCK_COMMAND.format(ip=ip)
    try:
        subprocess.run(shlex.split(cmd), check=True)
        print(f"[INFO] Unblocked ip {ip} after {duration} seconds.", flush=True)
    except Exception as e:
        print(f"[ERROR] Failed to unblock ip {ip}: {e}", flush=True)

def maybe_block_ip(ip: str, duration: int = DEFAULT_BLOCK_DURATION):
    if not ENABLE_IP_BLOCK:
        return False

    if not is_valid_ip(ip):
        print(f"[ERROR] Invalid ip address for blocking: {ip}", flush=True)
        return False

    block_cmd = BLOCK_COMMAND.format(ip=ip)
    try:
        subprocess.run(shlex.split(block_cmd), check=True)
        print(f"[INFO] Blocked ip {ip} for {duration} seconds.", flush=True)
        
        # Start a thread to unblock after 'duration' seconds
        threading.Thread(target=unblock_ip_later, args=(ip, duration), daemon=True).start()
        return True
    except Exception as e:
        print(f"[ERROR] Failed to block ip {ip}: {e}", flush=True)
        return False