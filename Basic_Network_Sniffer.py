import subprocess
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP


# Get the current network name (SSID) for Wi-Fi
def get_network_name():
    try:
        result = subprocess.check_output("netsh wlan show interfaces", shell=True)
        result = result.decode('utf-8', errors="backslashreplace")
        for line in result.split('\n'):
            if "SSID" in line:
                return line.split(":")[1].strip()
    except Exception as e:
        return "Unknown Network"

# Calculate network latency (ping to google.com)
def get_latency(host="8.8.8.8"):
    try:
        ping = subprocess.Popen(
            ["ping", "-c", "1", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, error = ping.communicate()
        out = out.decode("utf-8")
        if "time=" in out:
            latency = out.split("time=")[-1].split(" ms")[0]
            return float(latency)
        else:
            return None
    except Exception as e:
        return None

# Track the amount of data sniffed
start_time = time.time()
total_bytes = 0

# Analyze packet for additional information
def packet_analysis(packet):
    global total_bytes
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_size = len(packet)
        total_bytes += packet_size

        # Check if it's TCP, UDP, or ICMP
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = None
            dst_port = None
        else:
            protocol = "Other"
            src_port = None
            dst_port = None

        # Determine if the traffic is unicast, multicast, or broadcast
        if ip_dst.startswith("224.") or ip_dst.startswith("239."):
            traffic_type = "Multicast"
        elif ip_dst == "255.255.255.255":
            traffic_type = "Broadcast"
        else:
            traffic_type = "Unicast"

        # Output the packet details
        print(f'[{protocol}] {ip_src}:{src_port} --> {ip_dst}:{dst_port} | '
              f'Traffic Type: {traffic_type} | Size: {packet_size} bytes')

# Calculate bandwidth every second
def calculate_bandwidth():
    elapsed_time = time.time() - start_time
    if elapsed_time > 0:
        bandwidth = (total_bytes * 8) / elapsed_time  # Convert bytes to bits
        print(f"Current Bandwidth: {bandwidth / 1000:.2f} Kbps")

# Display network details before sniffing
network_name = get_network_name()
latency = get_latency()
print(f"Connected to Network: {network_name}")
print(f"Network Latency: {latency} ms (to google.com)")

# Start sniffing the network for packets
print("Sniffing... Press Ctrl+C to stop.")
try:
    while True:
        sniff(prn=packet_analysis, store=False, timeout=1)
        calculate_bandwidth()
except KeyboardInterrupt:
    print("Sniffing stopped.")
