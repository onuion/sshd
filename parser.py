import re
import time
import uuid

FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>[\w.\-@]+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)( ssh\d*)?"
)

INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>[\w.\-@]+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)

ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>[\w-]+) for (?P<user>[\w.\-@]+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)( ssh\d*)?(?P<rest>.*)"
)

DISCONNECTED_RE = re.compile(
    r"Disconnected from user (?P<user>[\w.\-@]+) (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)

CONNECTION_CLOSED_RE = re.compile(
    r"Connection closed by authenticating user (?P<user>[\w.\-@]+) (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)

def extract_fingerprint(rest: str):
    if not rest:
        return None
   
    cleaned = rest.strip()
    return cleaned if cleaned else None

def parse_ssh_log_line(line: str):
    line = line.strip()
    now = time.time()

    m = FAILED_PASSWORD_RE.search(line)
    if m:
        return {
            "event": "failed_password",
            "timestamp": now,
            "username": m.group("user"),
            "ip": m.group("ip"),
            "port": int(m.group("port")),
        }

    m = INVALID_USER_RE.search(line)
    if m:
        return {
            "event": "invalid_user",
            "timestamp": now,
            "username": m.group("user"),
            "ip": m.group("ip"),
            "port": int(m.group("port")),
        }

    m = ACCEPTED_RE.search(line)
    if m:
        method = m.group("method").lower()
        rest = m.group("rest")
        return {
            "event": f"accepted_{method}",
            "timestamp": now,
            "username": m.group("user"),
            "ip": m.group("ip"),
            "port": int(m.group("port")),
            "auth_method": method,
            "session_id": f"ssh_{uuid.uuid4().hex}",
            "fingerprint": extract_fingerprint(rest) if method == "publickey" else None,
        }

    m = DISCONNECTED_RE.search(line)
    if m:
        return {
            "event": "disconnected",
            "timestamp": now,
            "username": m.group("user"),
            "ip": m.group("ip"),
            "port": int(m.group("port")),
        }

    m = CONNECTION_CLOSED_RE.search(line)
    if m:
        return {
            "event": "connection_closed",
            "timestamp": now,
            "username": m.group("user"),
            "ip": m.group("ip"),
            "port": int(m.group("port")),
        }

    return None