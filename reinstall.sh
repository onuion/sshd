#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${RED}🧹 Removing existing Onuion SSHD installation...${NC}"

# 1. Stop and disable the service
sudo systemctl stop onuion-agent 2>/dev/null
sudo systemctl disable onuion-agent 2>/dev/null

# 2. Cleanup files
sudo rm -rf /opt/onuion-sshd
sudo rm -f /etc/systemd/system/onuion-agent.service
sudo rm -f /usr/local/bin/osshd
sudo rm -f /var/run/onuion-sshd.sock

sudo systemctl daemon-reload

echo -e "${GREEN}🚀 Reinstalling from GitHub...${NC}"

# 3. Clone to a temporary directory (for a clean install independent of current directory)
TEMP_DIR=$(mktemp -d)
cd $TEMP_DIR
git clone https://github.com/onuion/sshd.git onuion-sshd
cd onuion-sshd

# 4. Install dependencies
pip3 install -r requirements.txt --quiet

# 5. Create directory and copy files
sudo mkdir -p /opt/onuion-sshd
sudo cp -r ./* /opt/onuion-sshd/

# 6. Setup and start the service
sudo cp onuion-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable onuion-agent
sudo systemctl start onuion-agent

# 7. Install CLI tool (osshd)
sudo ln -sf /opt/onuion-sshd/cli.py /usr/local/bin/osshd
sudo chmod +x /opt/onuion-sshd/cli.py

# 8. Cleanup
cd /
rm -rf $TEMP_DIR

echo -e "${GREEN}✅ Reinstallation complete! Onuion SSHD is up and running.${NC}"
echo -e "You can check status with: ${RED}osshd status${NC}"
