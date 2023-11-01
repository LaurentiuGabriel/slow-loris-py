from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

packets = sniff(iface="eth0", count=100, prn=packet_callback)

wrpcap("captured_packets.pcap", packets)
