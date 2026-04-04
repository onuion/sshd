import hashlib

def _safe_geo(ip: str):
    return {
        "country": "UNKNOWN",
        "city": "UNKNOWN"
    }

def build_device_fingerprint(username, ip, auth_method, fingerprint=None):
    raw = f"{username}:{ip}:{auth_method}:{fingerprint or 'none'}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def build_requests_from_state(ip_data, event):
    requests = []

    for ts in list(ip_data.get("failed_attempts", [])):
        requests.append({
            "timestamp": ts,
            "method": "SSH",
            "endpoint": "auth/failed_password"
        })

    for item in list(ip_data.get("accepted_attempts", [])):
        requests.append({
            "timestamp": item["timestamp"],
            "method": "SSH",
            "endpoint": f"auth/accepted/{item['auth_method']}"
        })

    requests.append({
        "timestamp": event["timestamp"],
        "method": "SSH",
        "endpoint": f"event/{event['event']}"
    })

    requests.sort(key=lambda x: x["timestamp"])
    return requests[-50:]

def build_session_data(event, state):
    ip = event["ip"]
    username = event.get("username") or "unknown"
    auth_method = event.get("auth_method", "password")
    session_id = event.get("session_id", f"ssh_{ip}_{username}")

    ip_data = state.get_ip_data(ip) or {}
    user_data = state.get_user_data(username) or {}

    ip_history = list(user_data.get("ip_history", [])) or [ip]
    accepted_ips = list(user_data.get("accepted_ips", []))
    key_fps = list(user_data.get("key_fingerprints", []))

    initial_ip = accepted_ips[0] if accepted_ips else (ip_history[0] if ip_history else ip)

    current_geo = _safe_geo(ip)
    initial_geo = _safe_geo(initial_ip)

    current_fp = build_device_fingerprint(
        username=username,
        ip=ip,
        auth_method=auth_method,
        fingerprint=event.get("fingerprint")
    )

    initial_fp = key_fps[0] if key_fps else current_fp

    return {
        "current_ip": ip,
        "initial_ip": initial_ip,
        "ip_history": ip_history if ip_history else [ip],
        "current_geo": current_geo,
        "initial_geo": initial_geo,
        "current_device": {"fingerprint": current_fp},
        "initial_device": {"fingerprint": initial_fp},
        "current_browser": {},
        "initial_browser": {},
        "requests": build_requests_from_state(ip_data, event),
        "session_duration_seconds": 0.5,
        "current_session_id": session_id,
        "initial_session_id": list(user_data.get("session_ids", []))[0] if list(user_data.get("session_ids", [])) else session_id,
        "current_cookies": {},
        "initial_cookies": {},
        "current_referrer": "",
        "initial_referrer": ""
    }