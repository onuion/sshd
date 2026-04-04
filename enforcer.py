import shlex
import subprocess
from config import ENABLE_IP_BLOCK, BLOCK_COMMAND

def maybe_block_ip(ip: str):
    if not ENABLE_IP_BLOCK:
        return False

    cmd = BLOCK_COMMAND.format(ip=ip)
    try:
        subprocess.run(shlex.split(cmd), check=True)
        return True
    except Exception as e:
        print(f"[ERROR] failed to block ip {ip}: {e}", flush=True)
        return False