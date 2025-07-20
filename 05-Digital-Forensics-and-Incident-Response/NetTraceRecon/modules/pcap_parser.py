import pyshark

def process_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    return [pkt for pkt in cap]
