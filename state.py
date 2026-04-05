import time
from collections import defaultdict, deque
from config import MAX_REQUEST_HISTORY, MAX_FAILED_HISTORY

class SSHState:
    def __init__(self):
        self.ip_state = defaultdict(self._new_ip_state)
        self.user_state = defaultdict(self._new_user_state)
        self.active_sessions = {}

    def _new_ip_state(self):
        return {
            "first_seen": time.time(),
            "last_seen": time.time(),
            "failed_attempts": deque(maxlen=MAX_FAILED_HISTORY),
            "accepted_attempts": deque(maxlen=MAX_REQUEST_HISTORY),
            "invalid_users": deque(maxlen=MAX_REQUEST_HISTORY),
            "all_users": deque(maxlen=MAX_REQUEST_HISTORY),
            "session_ids": deque(maxlen=MAX_REQUEST_HISTORY),
        }

    def _new_user_state(self):
        return {
            "first_seen": time.time(),
            "last_seen": time.time(),
            "ip_history": deque(maxlen=MAX_REQUEST_HISTORY),
            "accepted_ips": deque(maxlen=MAX_REQUEST_HISTORY),
            "failed_ips": deque(maxlen=MAX_REQUEST_HISTORY),
            "key_fingerprints": deque(maxlen=MAX_REQUEST_HISTORY),
            "session_ids": deque(maxlen=MAX_REQUEST_HISTORY),
        }

    def register_failed(self, ip, username, timestamp):
        ip_entry = self.ip_state[ip]
        ip_entry["last_seen"] = timestamp
        ip_entry["failed_attempts"].append(timestamp)
        if username:
            ip_entry["all_users"].append(username)

        if username:
            user_entry = self.user_state[username]
            user_entry["last_seen"] = timestamp
            user_entry["ip_history"].append(ip)
            user_entry["failed_ips"].append(ip)

    def register_invalid_user(self, ip, username, timestamp):
        ip_entry = self.ip_state[ip]
        ip_entry["last_seen"] = timestamp
        ip_entry["invalid_users"].append(username)
        ip_entry["all_users"].append(username)

    def register_accepted(self, ip, username, session_id, auth_method, timestamp, fingerprint=None):
        ip_entry = self.ip_state[ip]
        ip_entry["last_seen"] = timestamp
        ip_entry["accepted_attempts"].append({
            "timestamp": timestamp,
            "username": username,
            "auth_method": auth_method,
            "session_id": session_id,
        })
        ip_entry["all_users"].append(username)
        ip_entry["session_ids"].append(session_id)

        user_entry = self.user_state[username]
        user_entry["last_seen"] = timestamp
        user_entry["ip_history"].append(ip)
        user_entry["accepted_ips"].append(ip)
        user_entry["session_ids"].append(session_id)
        if fingerprint:
            user_entry["key_fingerprints"].append(fingerprint)

    def is_ip_trusted(self, ip):
        ip_entry = self.ip_state.get(ip)
        if not ip_entry:
            return False
        return len(ip_entry["accepted_attempts"]) > 0

    def get_ip_data(self, ip):
        return self.ip_state.get(ip)

    def get_user_data(self, username):
        return self.user_state.get(username)