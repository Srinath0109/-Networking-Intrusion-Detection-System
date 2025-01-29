from packet_sniffer import capture_packets
from anomaly_detector import detect_intrusion

def main():
    print("🚀 Starting Network Intrusion Detection System...")
    
    for packet_data in capture_packets():
        if detect_intrusion(packet_data):
            print("[⚠️ ALERT] Intrusion detected!")

if __name__ == "__main__":
    main()
