from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\nSource IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        if TCP in packet:
            print("Protocol: TCP")
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            print("Protocol: UDP")
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")
        else:
            print("Protocol: Other")
        
        if packet.payload:
            print(f"Payload Data: {bytes(packet.payload)}")

def start_sniffer():
    print("Starting packet sniffer...")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    try:
        start_sniffer()
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
