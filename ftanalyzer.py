import pyshark
from collections import Counter
import sys
import asyncio
import os

def analyze_pcap(pcap_file, output_file):
    pcap = pyshark.FileCapture(pcap_file, keep_packets=False)

    type_counter = Counter()
    subtype_counter = Counter()
    packet_counter = 0
    broadcast_counter = 0

    for pkt in pcap:
        if 'wlan' in pkt:
            type = int(pkt.wlan.fc_type)
            subtype = int(pkt.wlan.fc_subtype)
            
            type_counter[type] += 1
            subtype_counter[(type, subtype)] += 1
            packet_counter += 1
            
            # Check for broadcast frames
            if hasattr(pkt.wlan, 'da') and pkt.wlan.da == 'ff:ff:ff:ff:ff:ff':
                broadcast_counter += 1

    with open(output_file, "w", encoding="utf-8") as output:
        # Map numeric types to names
        type_names = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}

        output.write(f"Total packets analyzed: {packet_counter}\n\n")

        output.write("Amount of packets per main frame type:\n")
        for t, count in type_counter.items():
            percentage = (count / packet_counter) * 100
            output.write(f"{type_names.get(t,t)}: {count} ({percentage:.2f}%)\n\n")

        # Broadcast frames
        broadcast_percentage = (broadcast_counter / packet_counter) * 100
        output.write(f"Broadcast frames: {broadcast_counter} ({broadcast_percentage:.2f}%)\n\n")

        subtype_names = {
        # --------------------
        # Management (type 0)
        # --------------------
        (0, 0):  "Association Request",
        (0, 1):  "Association Response",
        (0, 2):  "Reassociation Request",
        (0, 3):  "Reassociation Response",
        (0, 4):  "Probe Request",
        (0, 5):  "Probe Response",
        (0, 6):  "Timing Advertisement",
        (0, 7):  "Reserved",
        (0, 8):  "Beacon",
        (0, 9):  "ATIM",
        (0,10):  "Disassociation",
        (0,11):  "Authentication",
        (0,12):  "Deauthentication",
        (0,13):  "Action",
        (0,14):  "Action No Ack",
        (0,15):  "Reserved",

        # --------------------
        # Control (type 1)
        # --------------------
        (1, 0):  "Reserved",
        (1, 1):  "Reserved",
        (1, 2):  "Trigger",
        (1, 3):  "TACK",
        (1, 4):  "Beamforming Report Poll",
        (1, 5):  "VHT/HE NDP Announcement",
        (1, 6):  "Control Frame Extension",
        (1, 7):  "Control Wrapper",
        (1, 8):  "Block Ack Request (BAR)",
        (1, 9):  "Block Ack (BA)",
        (1,10):  "PS-Poll",
        (1,11):  "RTS",
        (1,12):  "CTS",
        (1,13):  "ACK",
        (1,14):  "CF-End",
        (1,15):  "CF-End + CF-Ack",

        # --------------------
        # Data (type 2)
        # --------------------
        (2, 0):  "Data",
        (2, 1):  "Data + CF-Ack",
        (2, 2):  "Data + CF-Poll",
        (2, 3):  "Data + CF-Ack + CF-Poll",
        (2, 4):  "Null (No Data)",
        (2, 5):  "CF-Ack (No Data)",
        (2, 6):  "CF-Poll (No Data)",
        (2, 7):  "CF-Ack + CF-Poll (No Data)",
        (2, 8):  "QoS Data",
        (2, 9):  "QoS Data + CF-Ack",
        (2,10):  "QoS Data + CF-Poll",
        (2,11):  "QoS Data + CF-Ack + CF-Poll",
        (2,12):  "QoS Null",
        (2,13):  "Reserved",
        (2,14):  "QoS CF-Poll (No Data)",
        (2,15):  "QoS CF-Ack + CF-Poll (No Data)",

        # --------------------
        # Extension (type 3)
        # --------------------
        (3, 0):  "DMG Beacon",
        (3, 1):  "S1G Beacon",
        (3, 2):  "Reserved",
        (3, 3):  "Reserved",
        (3, 4):  "Reserved",
        (3, 5):  "Reserved",
        (3, 6):  "Reserved",
        (3, 7):  "Reserved",
        (3, 8):  "Reserved",
        (3, 9):  "Reserved",
        (3,10):  "Reserved",
        (3,11):  "Reserved",
        (3,12):  "Reserved",
        (3,13):  "Reserved",
        (3,14):  "Reserved",
        (3,15):  "Reserved",
        }

        # subtypes sorted in reverse order of frequency
        sorted_subtypes = subtype_counter.most_common()
        sorted_subtypes.reverse()

        output.write("\nAmount of packets per frame subtype:\n")
        for st, count in sorted_subtypes:
            percentage = (count / packet_counter) * 100
            output.write(f"{subtype_names.get(st, f'Unknown subtype {st}')}: {count} ({percentage:.2f}%)\n\n")

        # frames not seen
        output.write("\nFrame subtypes not observed in the capture:\n")
        all_frames = set(subtype_names.keys())
        observed_frames = set(subtype_counter.keys())
        missing_frames = all_frames - observed_frames

        for st in missing_frames:
            output.write(f"{subtype_names.get(st, f'Unknown subtype {st}')}\n\n")

        threshold = 0.10 * packet_counter
        total_count = 0
        output.write(f"\nBottom 10% of frame subtypes:\n")
        for st, count in sorted_subtypes:
            total_count += count
            percentage = (count / packet_counter) * 100
            output.write(f"{subtype_names.get(st, f'Unknown subtype {st}')}: {count} ({percentage:.2f}%)\n\n")
            if total_count >= threshold:
                break
        
    pcap.close()
    print(f"Analysis complete. Results saved to '{output_file}'")


def main():
    asyncio.set_event_loop(asyncio.new_event_loop())

    if len(sys.argv) < 2:
        print("Usage: python ftanalyzer.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_file = f"{os.path.splitext(pcap_file)[0]}_results.txt"

    try:
        analyze_pcap(pcap_file, output_file)
    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error analyzing file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

