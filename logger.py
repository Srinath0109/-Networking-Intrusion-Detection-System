import datetime

def log_intrusion(packet_data):
    """Logs detected intrusions."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("intrusions.log", "a") as log_file:
        log_entry = f"[{timestamp}] Intrusion detected from {packet_data['src_ip']} to {packet_data['dst_ip']} | Protocol: {packet_data['protocol']}\n"
        log_file.write(log_entry)
    print("📜 Intrusion logged.")
