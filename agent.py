import json
import os
import socket
import threading
import time
from datetime import datetime

from onuion import analyze_risk

from config import SOCKET_PATH, SOCKET_BACKLOG, BLOCK_THRESHOLD, ALERT_THRESHOLD, AUTH_LOG_PATH
from state import SSHState
from normalizer import build_session_data
from enforcer import maybe_block_ip
from parser import parse_ssh_log_line

state = SSHState()

def normalize_ip(ip):
    if not ip:
        return "unknown"
    if ip.startswith("::ffff:"):
        return ip[7:]
    return ip

def log_json(data):
    print(json.dumps(data, ensure_ascii=False), flush=True)

def analyze_auth_request(username, ip, pam_type="auth"):
    ip = normalize_ip(ip)
    timestamp = time.time()

    event = {
        "event": "pam_auth",
        "timestamp": timestamp,
        "username": username or "unknown",
        "ip": ip or "unknown",
        "auth_method": "password",
        "session_id": f"ssh_{username}_{int(timestamp)}",
        "fingerprint": None,
    }

    # IMPORTANT: Check if IP is already trusted based on previous successful logins
    is_trusted = state.is_ip_trusted(ip)
    if is_trusted:
        log_json({
            "ts": datetime.utcnow().isoformat() + "Z",
            "source": "onuion-sshd",
            "message": f"IP {ip} is already trusted.",
            "ip": ip
        })

    state.register_failed(ip, username, timestamp)

    session_data = build_session_data(event, state)

    result = analyze_risk(session_data)

    risk_score = getattr(result, "riskScore", 0)
    risks = getattr(result, "risk", [])
    inference_time_ms = getattr(result, "inference_time_ms", 0.0)

    decision = "continue_connection"
    blocked = False

    # Check for specific risks and score threshold for 1-hour block
    block_reasons = []
    
    # Rule 1: Special risks (ip_mismatch and rapid_ip_change)
    if "ip_mismatch" in risks and "rapid_ip_change" in risks:
        block_reasons.append("looks_ssh_scan_bot")
        
    # Rule 2: Score > 49
    if risk_score > 49:
        block_reasons.append("high_risk_score")

    if block_reasons:
        if is_trusted:
            # Skip blocking for trusted IPs
            decision = "continue_connection"
            blocked = False
            block_reasons.append("skipped_because_trusted")
        else:
            decision = "close_connection"
            # Block for 1 hour (3600 seconds)
            blocked = maybe_block_ip(ip, duration=3600)
    elif risk_score >= ALERT_THRESHOLD:
        decision = "continue_connection"

    response = {
        "decision": decision,
        "riskScore": risk_score,
        "risk": risks,
        "blocked": blocked,
        "inference_time_ms": inference_time_ms
    }

    log_json({
        "ts": datetime.utcnow().isoformat() + "Z",
        "source": "onuion-sshd",
        "event": "pam_auth",
        "username": username,
        "ip": ip,
        "pam_type": pam_type,
        "riskScore": risk_score,
        "risk": risks,
        "decision": decision,
        "blocked": blocked,
        "inference_time_ms": inference_time_ms
    })

    return response

def handle_client(conn):
    try:
        raw = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw += chunk

        if not raw:
            return

        data = json.loads(raw.decode())
        username = data.get("username", "unknown")
        ip = data.get("ip", "unknown")
        pam_type = data.get("pam_type", "auth")

        response = analyze_auth_request(username, ip, pam_type)
        conn.sendall(json.dumps(response).encode())

    except Exception as e:
        err = {
            "decision": "continue_connection",
            "error": str(e)
        }
        try:
            conn.sendall(json.dumps(err).encode())
        except Exception:
            pass

        log_json({
            "ts": datetime.utcnow().isoformat() + "Z",
            "source": "onuion-sshd",
            "level": "error",
            "message": str(e)
        })
    finally:
        try:
            conn.close()
        except Exception:
            pass

def cleanup_socket():
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

def tail_auth_log(state):
    """Background thread to tail the SSH log and update state with successes/failures."""
    if not os.path.exists(AUTH_LOG_PATH):
        log_json({
            "ts": datetime.utcnow().isoformat() + "Z",
            "source": "onuion-sshd",
            "level": "warning",
            "message": f"Log file not found: {AUTH_LOG_PATH}. Trusted IP detection disabled."
        })
        return

    log_json({
        "ts": datetime.utcnow().isoformat() + "Z",
        "source": "onuion-sshd",
        "message": f"Starting log tailer on {AUTH_LOG_PATH}"
    })

    try:
        # Initial scan: Read last ~5000 lines (roughly 500kb) to populate initial trust state
        trusted_count = 0
        with open(AUTH_LOG_PATH, "r") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            # Seek back roughly 500kb
            f.seek(max(0, size - 524288))
            lines = f.readlines()
            # Skip first line as it might be partial
            if len(lines) > 1:
                for line in lines[1:]:
                    parsed = parse_ssh_log_line(line)
                    if parsed and parsed["event"].startswith("accepted_"):
                        ip = normalize_ip(parsed["ip"])
                        if not state.is_ip_trusted(ip):
                            trusted_count += 1
                        state.register_accepted(
                            ip=ip,
                            username=parsed["username"],
                            session_id=parsed.get("session_id"),
                            auth_method=parsed.get("auth_method"),
                            timestamp=parsed["timestamp"],
                            fingerprint=parsed.get("fingerprint")
                        )
                    elif parsed and parsed["event"] == "failed_password":
                        state.register_failed(normalize_ip(parsed["ip"]), parsed["username"], parsed["timestamp"])
        
        log_json({
            "ts": datetime.utcnow().isoformat() + "Z",
            "source": "onuion-sshd",
            "message": f"Initial log scan complete. Found {trusted_count} unique trusted IPs in history."
        })

        # Continues tailing from the end
        with open(AUTH_LOG_PATH, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                parsed = parse_ssh_log_line(line)
                if parsed:
                    if parsed["event"].startswith("accepted_"):
                        state.register_accepted(
                            ip=normalize_ip(parsed["ip"]),
                            username=parsed["username"],
                            session_id=parsed.get("session_id"),
                            auth_method=parsed.get("auth_method"),
                            timestamp=parsed["timestamp"],
                            fingerprint=parsed.get("fingerprint")
                        )
                    elif parsed["event"] == "failed_password":
                        state.register_failed(normalize_ip(parsed["ip"]), parsed["username"], parsed["timestamp"])

    except Exception as e:
        log_json({
            "ts": datetime.utcnow().isoformat() + "Z",
            "source": "onuion-sshd",
            "level": "error",
            "message": f"Log tailer error: {e}"
        })

def run_server():
    cleanup_socket()

    # Start log tailer thread
    threading.Thread(target=tail_auth_log, args=(state,), daemon=True).start()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o666)
    server.listen(SOCKET_BACKLOG)

    log_json({
        "ts": datetime.utcnow().isoformat() + "Z",
        "source": "onuion-sshd",
        "message": f"Listening on {SOCKET_PATH}"
    })

    try:
        while True:
            conn, _ = server.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
    finally:
        server.close()
        cleanup_socket()

if __name__ == "__main__":
    run_server()