import re
import time
import uuid

FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>[\w.\-@]+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) ssh2"
)

INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>[\w.\-@]+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)

ACCEPTED_PASSWORD_RE = re.compile(
    r"Accepted password for (?P<user>[\w.\-@]+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) ssh2"
)

ACCEPTED_PUBLICKEY_RE = re.compile(
    r"Accepted publickey for (?P<user>[\w.\-@]+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) ssh2(?P<rest>.*)"
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

    m = ACCEPTED_PASSWORD_RE.search(line)
    if m:
        return {
            "event": "accepted_password",
            "timestamp": now,
            "username": m.group("user"),
            "ip": m.group("ip"),
            "port": int(m.group("port")),
            "auth_method": "password",
            "session_id": f"ssh_{uuid.uuid4().hex}",
            "fingerprint": None,
        }

    m = ACCEPTED_PUBLICKEY_RE.search(line)
    if m:
        rest = m.group("rest")
        return {
            "event": "accepted_publickey",
            "timestamp": now,
            "username": m.group("user"),
            "ip": m.group("ip"),
            "port": int(m.group("port")),
            "auth_method": "publickey",
            "session_id": f"ssh_{uuid.uuid4().hex}",
            "fingerprint": extract_fingerprint(rest),
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