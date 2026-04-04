import json
import os
import socket
import sys

SOCKET_PATH = "/var/run/onuion-sshd.sock"

def main():
    username = os.environ.get("PAM_USER", "unknown")
    ip = os.environ.get("PAM_RHOST", "unknown")
    pam_type = os.environ.get("PAM_TYPE", "auth")

    payload = {
        "username": username,
        "ip": ip,
        "pam_type": pam_type
    }

    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect(SOCKET_PATH)
        client.sendall(json.dumps(payload).encode())
        client.shutdown(socket.SHUT_WR)

        response_raw = client.recv(4096).decode()
        response = json.loads(response_raw)

        decision = response.get("decision", "continue_connection")

        if decision == "close_connection":
            sys.exit(1)

        sys.exit(0)

    except Exception as e:
        print(f"[onuion-pam] fail-open error: {e}", file=sys.stderr)
        sys.exit(0)

if __name__ == "__main__":
    main()