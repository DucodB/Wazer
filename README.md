# Wazer

A wireless frame type analyzer for 802.11 (Wi-Fi) networks. Wazer captures packets in monitor mode and provides detailed statistics on frame types, subtypes, and broadcast traffic.

## Features

- **Packet Capture**: Captures wireless frames using tshark in monitor mode
- **Frame Type Analysis**: Categorizes frames into Management, Control, Data, and Extension types
- **Detailed Subtype Statistics**: Analyzes all 802.11 frame subtypes with frequency percentages
- **Broadcast Detection**: Identifies and counts broadcast frames
- **Low-Frequency Analysis**: Reports the bottom 10% of frame subtypes
- **Missing Frame Detection**: Lists frame subtypes not observed in the capture

## Requirements

- Linux-based system
- Python 3.x
- TShark (Wireshark command-line tool)
- Wireless interface capable of monitor mode
- Root/sudo privileges (required for packet capture)

### Python Dependencies

- `pyshark` (automatically installed by the script)

## Installation

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd Wazer
   ```

2. Install TShark:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install tshark

   # Fedora/RHEL
   sudo dnf install wireshark-cli

   # Arch Linux
   sudo pacman -S wireshark-cli
   ```

3. Ensure your wireless interface supports monitor mode:
   ```bash
   iw list | grep -A 10 "Supported interface modes"
   ```

## Usage

### Automatic Capture and Analysis

Run the automated script to capture packets for 10 minutes and analyze them:

```bash
./analyze.sh
```

**Note**: You may need to modify the `INTERFACE` variable in `analyze.sh` to match your wireless interface name (default is `wlan0`).

The script will:
1. Create a virtual environment
2. Install pyshark if needed
3. Capture packets for 10 minutes (600 seconds)
4. Save the capture to `pcap_files/` directory with timestamp
5. Analyze the captured packets
6. Display statistics

### Manual Analysis

To analyze an existing pcap file:

```bash
python3 ftanalyzer.py <path-to-pcap-file>
```

Example:
```bash
python3 ftanalyzer.py pcap_files/campus_2026-02-17_14-30-00.pcap
```

## Output

The analyzer provides the following statistics:

- **Total Packets**: Number of packets analyzed
- **Frame Type Distribution**: Percentage breakdown by main frame types
- **Broadcast Frames**: Count and percentage of broadcast traffic
- **Frame Subtype Distribution**: Detailed list of all subtypes (sorted by frequency)
- **Missing Frame Subtypes**: Frame types not seen in the capture
- **Bottom 10%**: Least common frame subtypes

### Example Output

```
Total packets analyzed: 15432

Amount of packets per main frame type:
Management: 8234 (53.36%)
Control: 4521 (29.29%)
Data: 2677 (17.35%)

Broadcast frames: 3456 (22.40%)

Amount of packets per frame subtype:
Beacon: 5123 (33.19%)
ACK: 4234 (27.44%)
...
```

## Configuration

### Modifying Capture Parameters

Edit `analyze.sh` to customize:

- **Interface**: Change `INTERFACE="wlan0"` to your wireless interface
- **Duration**: Modify `-a duration:600` (in seconds)
- **Snapshot Length**: Change `-s 128` to capture more/less of each packet
- **Location Tag**: Modify `LOCATION="campus"` for different naming


## How It Works

1. **Packet Capture**: Uses TShark to capture 802.11 frames in monitor mode
2. **Parsing**: PyShark reads the pcap file and extracts WLAN layer information
3. **Classification**: Frames are categorized by type and subtype fields
4. **Statistics**: Counters track occurrences and calculate percentages
5. **Reporting**: Results are displayed in human-readable format

## Troubleshooting

### Interface Not in Monitor Mode
```bash
sudo ip link set <interface> down
sudo iw <interface> set monitor control
sudo ip link set <interface> up
```
