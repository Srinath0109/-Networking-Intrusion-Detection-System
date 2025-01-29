from scapy.all import sniff
from feature_extraction import extract_features

def capture_packets(interface="eth0"):
    """Capture live network packets and extract features."""
    def process_packet(packet):
        return extract_features(packet)
    
    print("🛜 Capturing network packets...")
    return sniff(iface=interface, prn=process_packet, store=0)
