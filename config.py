import os
SOCKET_PATH = "/var/run/onuion-sshd.sock"

BLOCK_THRESHOLD = 85
ALERT_THRESHOLD = 65

ENABLE_IP_BLOCK = False
BLOCK_COMMAND = "iptables -I INPUT -s {ip} -j DROP"
UNBLOCK_COMMAND = "iptables -D INPUT -s {ip} -j DROP"

DEFAULT_BLOCK_DURATION = 3600  # 1 hour in seconds
MAX_REQUEST_HISTORY = 20
MAX_FAILED_HISTORY = 10
SOCKET_BACKLOG = 50

# Log paths for different distributions
AUTH_LOG_PATH = "/var/log/auth.log" # For Ubuntu/Debian
if not os.path.exists(AUTH_LOG_PATH) and os.path.exists("/var/log/secure"):
    AUTH_LOG_PATH = "/var/log/secure" # For RHEL/CentOS