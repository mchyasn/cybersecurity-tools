from scapy.all import *

def parse_sessions(pcap_file):
    sessions = []
    packets = rdpcap(pcap_file)
    for packet in packets:
        if IP in packet:
            sessions.append((packet[IP].src, packet[IP].dst, packet.proto))
    return sessions
