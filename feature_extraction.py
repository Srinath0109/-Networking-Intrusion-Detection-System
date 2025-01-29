from scapy.all import IP, TCP, UDP, Raw

def extract_features(packet):
    """Extracts features from a network packet for intrusion detection."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload_size = len(packet[IP].payload)

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
        else:
            flags = 0

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "flags": flags,
            "payload_size": payload_size,
        }
    return None
