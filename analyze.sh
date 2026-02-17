#!/bin/bash

# Change to wireless interface capable of monitor mode
INTERFACE="wlan0"

if ! command -v tshark > /dev/null 2>&1; then
    echo "tshark is not installed. Please install it and rerun the script."
    exit 1
fi
ENV_DIR="tshark-env"
if [ ! -d "$ENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$ENV_DIR"
fi

echo Activating virtual environment...
source "$ENV_DIR/bin/activate"
if ! pip show pyshark > /dev/null 2>&1; then
    echo "pyshark is not installed, installing now..."
    pip install pyshark
fi

LOCATION="campus"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
PCAP_FILE=pcap_files/"$LOCATION"_"$TIMESTAMP".pcap
mkdir -p "pcap_files"
echo "Starting packet capture for 10 minutes..."
sudo tshark -i "$INTERFACE" -I -a duration:600 -s 128 -w "$PCAP_FILE"
echo Packet capture completed and stored in "$PCAP_FILE"
echo Analyzing the pcap file...
echo "-------------------------------------------"
python3 ftanalyzer.py "$PCAP_FILE"
echo "-------------------------------------------"
deactivate
echo "Done"