#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}🚀 Starting Onuion SSHD installation...${NC}"

# 1. Prerequisites check (apt-based systems)
if [ -f /usr/bin/apt ]; then
    echo -e "Installing python3-venv and iptables..."
    sudo apt update -qq && sudo apt install -y python3-venv iptables -qq
fi

# 2. Cleanup old parts if they exist
echo -e "Cleaning up previous installation..."
sudo systemctl stop onuion-agent 2>/dev/null
sudo systemctl disable onuion-agent 2>/dev/null
sudo rm -rf /opt/onuion-sshd
sudo rm -f /etc/systemd/system/onuion-agent.service
sudo rm -f /usr/local/bin/osshd

# 3. Create app directory
sudo mkdir -p /opt/onuion-sshd
sudo cp -r ./* /opt/onuion-sshd/

# 4. Initialize virtual environment and install dependencies
echo -e "Setting up virtual environment and dependencies..."
cd /opt/onuion-sshd
sudo python3 -m venv venv
sudo /opt/onuion-sshd/venv/bin/pip install --upgrade pip --quiet
sudo /opt/onuion-sshd/venv/bin/pip install -r requirements.txt --quiet

# 5. Install systemd service
echo -e "Configuring systemd service..."
sudo cp onuion-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable onuion-agent
sudo systemctl start onuion-agent

# 6. Setup CLI tool (osshd)
echo -e "Installing the 'osshd' command..."
sudo ln -sf /opt/onuion-sshd/cli.py /usr/local/bin/osshd
sudo chmod +x /opt/onuion-sshd/cli.py

echo -e "${GREEN}✅ Onuion SSHD installed successfully!${NC}"
echo -e "============================================"
echo -e "Quick Check:  osshd status"
echo -e "Configuration: osshd config --list"
echo -e "Activate blocking: osshd config --set ENABLE_IP_BLOCK=True"
echo -e "============================================"
