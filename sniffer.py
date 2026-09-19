from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

packet_count = 0


def analyze_packet(packet):
    global packet_count

    if IP in packet:
        packet_count += 1

        # Source and destination IP
        source = packet[IP].src
        destination = packet[IP].dst

        # Identify protocol
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        # Get payload
        payload = ""

        if packet.haslayer("Raw"):
            payload = packet["Raw"].load

        # Time of packet
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Display packet information
        print("\n" + "=" * 50)
        print(f"Packet Number  : {packet_count}")
        print(f"Time           : {timestamp}")
        print(f"Source IP      : {source}")
        print(f"Destination IP : {destination}")
        print(f"Protocol       : {protocol}")
        print(f"Payload        : {payload}")
        print("=" * 50)

        # Save results to file
        with open("scan_results.txt", "a") as file:
            file.write(
                f"Packet {packet_count} | "
                f"Time: {timestamp} | "
                f"Source: {source} | "
                f"Destination: {destination} | "
                f"Protocol: {protocol} | "
                f"Payload: {payload}\n"
            )


print("=" * 50)
print("             BASIC NETWORK SNIFFER")
print("=" * 50)
print("Starting packet capture...")
print("Press CTRL+C to stop.\n")

try:
    sniff(prn=analyze_packet, store=False)

except KeyboardInterrupt:
    print("\n" + "=" * 50)
    print("Packet capture stopped.")
    print(f"Total packets captured: {packet_count}")
    print("Results saved in scan_results.txt")
    print("=" * 50)